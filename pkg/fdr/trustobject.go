package fdr

import "crypto/x509"

const (
	TrustObjectMagic = "secb"
	TrustObjectSigning = "trst"
	TrustObjectTransport = "rssl"
	TrustObjectRevocation = "rvok"
)

type TrustObject struct {
	SigningCertificate *x509.Certificate
	TransportCertificate *x509.Certificate
	Revocation *x509.RevocationList
}

func parseTrustObject(data []byte) (*TrustObject, error) {

}