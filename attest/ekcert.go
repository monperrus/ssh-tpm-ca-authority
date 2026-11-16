package attest

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// NV index of the manufacturer-provisioned certificate for the ECC P-256 EK created from
// tpm2.ECCEKTemplate (TCG EK Credential Profile 2.0, section 2.2.1.5).
const EKCertNVIndexECC = tpm2.TPMHandle(0x01c0000a)

// maxNVChunk stays below TPM_PT_NV_BUFFER_MAX on common TPMs (often 768 or 1024 bytes).
const maxNVChunk = 512

var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// ReadEKCertificate returns the DER EK certificate the manufacturer stored in NV,
// or an error if the TPM has none (software TPMs and simulators usually have none).
func ReadEKCertificate(rwc transport.TPM) ([]byte, error) {
	pub, err := tpm2.NVReadPublic{NVIndex: EKCertNVIndexECC}.Execute(rwc)
	if err != nil {
		return nil, fmt.Errorf("no EK certificate in NV index %#x: %w", uint32(EKCertNVIndexECC), err)
	}
	contents, err := pub.NVPublic.Contents()
	if err != nil {
		return nil, err
	}
	var out []byte
	for off := uint16(0); off < contents.DataSize; {
		n := min(contents.DataSize-off, maxNVChunk)
		rsp, err := tpm2.NVRead{
			AuthHandle: tpm2.AuthHandle{Handle: EKCertNVIndexECC, Name: pub.NVName, Auth: tpm2.PasswordAuth(nil)},
			NVIndex:    tpm2.NamedHandle{Handle: EKCertNVIndexECC, Name: pub.NVName},
			Size:       n,
			Offset:     off,
		}.Execute(rwc)
		if err != nil {
			return nil, fmt.Errorf("reading EK certificate: %w", err)
		}
		out = append(out, rsp.Data.Buffer...)
		off += n
	}
	return trimDER(out)
}

// trimDER drops the padding some manufacturers leave after the certificate in NV.
func trimDER(b []byte) ([]byte, error) {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(b, &raw)
	if err != nil {
		return nil, fmt.Errorf("EK certificate is not DER: %w", err)
	}
	return b[:len(b)-len(rest)], nil
}

// EKTrust holds the manufacturer roots (and intermediates) an EK certificate must chain to.
type EKTrust struct {
	Roots         *x509.CertPool
	Intermediates *x509.CertPool
}

// LoadEKTrust reads PEM bundles of roots and intermediates.
func LoadEKTrust(rootsPEM, intermediatesPEM string) (*EKTrust, error) {
	t := &EKTrust{Roots: x509.NewCertPool(), Intermediates: x509.NewCertPool()}
	b, err := os.ReadFile(rootsPEM)
	if err != nil {
		return nil, err
	}
	if !t.Roots.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("no certificate in %s", rootsPEM)
	}
	if intermediatesPEM != "" {
		b, err := os.ReadFile(intermediatesPEM)
		if err != nil {
			return nil, err
		}
		if !t.Intermediates.AppendCertsFromPEM(b) {
			return nil, fmt.Errorf("no certificate in %s", intermediatesPEM)
		}
	}
	return t, nil
}

// VerifyEKCertificate checks that der chains to a trusted manufacturer root and certifies ek,
// the EK the credential challenge is encrypted to.
func (t *EKTrust) VerifyEKCertificate(der []byte, ek *tpm2.TPMTPublic, now time.Time) error {
	if len(der) == 0 {
		return errors.New("no EK certificate")
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("parsing EK certificate: %w", err)
	}
	// TCG EK certificates carry a critical subjectAltName holding only a directoryName
	// (TPM manufacturer, model, version), which Go reports as unhandled.
	unhandled := cert.UnhandledCriticalExtensions[:0]
	for _, oid := range cert.UnhandledCriticalExtensions {
		if !oid.Equal(oidSubjectAltName) {
			unhandled = append(unhandled, oid)
		}
	}
	cert.UnhandledCriticalExtensions = unhandled
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:         t.Roots,
		Intermediates: t.Intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return fmt.Errorf("EK certificate does not chain to a trusted TPM manufacturer: %w", err)
	}
	ekPub, err := GetECDSAFromTPMTPublic(ek)
	if err != nil {
		return fmt.Errorf("EK is not an ECC key: %w", err)
	}
	certPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !certPub.Equal(ekPub) {
		return errors.New("EK certificate is for another key than the challenged EK")
	}
	return nil
}
