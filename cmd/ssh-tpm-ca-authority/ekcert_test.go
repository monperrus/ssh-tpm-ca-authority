package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/foxboron/ssh-tpm-ca-authority/attest"
	"github.com/foxboron/ssh-tpm-ca-authority/client"
	"github.com/foxboron/ssh-tpm-ca-authority/server"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// manufacturer is a fake TPM vendor CA that issues EK certificates shaped like real ones.
type manufacturer struct {
	key  *ecdsa.PrivateKey
	cert *x509.Certificate
}

func newManufacturer(t *testing.T, name string) *manufacturer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &manufacturer{k, c}
}

func (m *manufacturer) pemFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "roots.pem")
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.cert.Raw})
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// ekCert issues an EK certificate for pub with an empty subject and a critical
// subjectAltName holding only a directoryName, as TCG EK certificates do.
func (m *manufacturer) ekCert(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	rdn, err := asn1.Marshal(pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{
		{Type: asn1.ObjectIdentifier{2, 23, 133, 2, 1}, Value: "id:53494D00"}, // tpmManufacturer
	}}.ToRDNSequence())
	if err != nil {
		t.Fatal(err)
	}
	san, err := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: rdn}})
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:       big.NewInt(2),
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(24 * time.Hour),
		KeyUsage:           x509.KeyUsageKeyAgreement,
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{{2, 23, 133, 8, 1}},
		ExtraExtensions:    []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Critical: true, Value: san}},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, m.cert, pub, m.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func simulatorEK(t *testing.T, rwc transport.TPMCloser) *ecdsa.PublicKey {
	t.Helper()
	h, pub, err := attest.ReadEKCert(rwc)
	if err != nil {
		t.Fatal(err)
	}
	keyfile.FlushHandle(rwc, h)
	k, err := attest.GetECDSAFromTPMTPublic(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// writeEKCert provisions der at the EK certificate NV index, as a manufacturer does.
func writeEKCert(t *testing.T, rwc transport.TPMCloser, der []byte) {
	t.Helper()
	pub := tpm2.TPMSNVPublic{
		NVIndex: attest.EKCertNVIndexECC,
		NameAlg: tpm2.TPMAlgSHA256,
		Attributes: tpm2.TPMANV{
			OwnerWrite: true, OwnerRead: true, AuthRead: true, NoDA: true,
			NT: tpm2.TPMNTOrdinary,
		},
		DataSize: uint16(len(der)),
	}
	if _, err := (tpm2.NVDefineSpace{
		AuthHandle: tpm2.TPMRHOwner,
		PublicInfo: tpm2.New2B(pub),
	}).Execute(rwc); err != nil {
		t.Fatal(err)
	}
	rp, err := tpm2.NVReadPublic{NVIndex: attest.EKCertNVIndexECC}.Execute(rwc)
	if err != nil {
		t.Fatal(err)
	}
	for off := 0; off < len(der); off += 512 {
		end := min(off+512, len(der))
		if _, err := (tpm2.NVWrite{
			AuthHandle: tpm2.TPMRHOwner,
			NVIndex:    tpm2.NamedHandle{Handle: attest.EKCertNVIndexECC, Name: rp.NVName},
			Data:       tpm2.TPM2BMaxNVBuffer{Buffer: der[off:end]},
			Offset:     uint16(off),
		}).Execute(rwc); err != nil {
			t.Fatal(err)
		}
	}
}

// issue runs the CA protocol against a server requiring EK certificates from roots. It returns
// the error of the full client flow and the server's answer to the attestation request.
func issue(t *testing.T, rwc transport.TPMCloser, roots string) (error, string) {
	t.Helper()
	h, _, err := attest.ReadEKCert(rwc)
	if err != nil {
		t.Fatal(err)
	}
	keyfile.FlushHandle(rwc, h)
	ca, err := keyfile.NewLoadableKey(rwc, tpm2.TPMAlgECC, 256, []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	as, err := server.NewTPMAttestServer(rwc, &server.Config{
		EKRoots: roots,
		Hosts: []*server.HostConf{{
			Host:   "test.local",
			CaFile: &server.UnmarshalTPMkey{TPMKey: ca},
			Users: []*server.UsersConf{
				{User: "fox", EK: fmt.Sprintf("%x", h.Name.Buffer), OIDCConnector: "none"},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(as.Handlers())
	defer ts.Close()
	userkey, rsp, err := keyfile.NewLoadableKeyWithResponse(rwc, tpm2.TPMAlgECC, 256, []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	ap, err := attest.NewAttestationParameters(rwc, userkey, rsp)
	if err != nil {
		t.Fatal(err)
	}
	keyfile.FlushHandle(rwc, ap.Handle.Handle)
	ap.Host, ap.User = "test.local", "fox"
	b, _ := json.Marshal(ap)
	r, err := http.Post(ts.URL+"/attest", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(r.Body)

	userkey, rsp, err = keyfile.NewLoadableKeyWithResponse(rwc, tpm2.TPMAlgECC, 256, []byte(""))
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.NewClient(ts.URL).GetCASignedKey(rwc, userkey, rsp, "fox", "test.local")
	return err, string(body)
}

func TestEKCertificate(t *testing.T) {
	vendor := newManufacturer(t, "Test TPM Manufacturer Root")
	other := newManufacturer(t, "Other Root")

	for _, tc := range []struct {
		name   string
		cert   func(rwc transport.TPMCloser) []byte // nil: nothing in NV
		roots  string
		wantOK bool
		reason string
	}{
		{"no EK certificate check configured, none in NV", nil, "", true, ""},
		{"EK certificate from trusted manufacturer", func(rwc transport.TPMCloser) []byte {
			return vendor.ekCert(t, simulatorEK(t, rwc))
		}, vendor.pemFile(t), true, ""},
		{"no EK certificate in NV", nil, vendor.pemFile(t), false, "no EK certificate"},
		{"EK certificate from untrusted manufacturer", func(rwc transport.TPMCloser) []byte {
			return other.ekCert(t, simulatorEK(t, rwc))
		}, vendor.pemFile(t), false, "does not chain to a trusted TPM manufacturer"},
		{"EK certificate for another key", func(rwc transport.TPMCloser) []byte {
			k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			return vendor.ekCert(t, &k.PublicKey)
		}, vendor.pemFile(t), false, "for another key than the challenged EK"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rwc, err := OpenSimulator()
			if err != nil {
				t.Fatal(err)
			}
			defer rwc.Close()
			if tc.cert != nil {
				writeEKCert(t, rwc, tc.cert(rwc))
			}
			err, body := issue(t, rwc, tc.roots)
			if tc.wantOK && err != nil {
				t.Fatalf("want certificate, got %v (attest: %s)", err, body)
			}
			if !tc.wantOK {
				if err == nil {
					t.Fatal("want rejection, got a certificate")
				}
				if !strings.Contains(body, tc.reason) {
					t.Fatalf("want rejection for %q, got %q", tc.reason, body)
				}
			}
		})
	}
}
