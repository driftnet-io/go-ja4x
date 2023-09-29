package ja4x

import (
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"strings"
)

// JA4X produces a JA4X hash for a parsed X509 certificate.
func JA4X(cert *x509.Certificate) string {
	rawComps := components(cert)

	var hashComps []string
	for _, c := range rawComps {
		hashComps = append(hashComps, hash12(c))
	}

	return strings.Join(hashComps, "_")
}

// JA4XWithRaw produces a JA4X hash for a parsed X509 certificate.
// It also returns the hash in a raw form.
func JA4XWithRaw(cert *x509.Certificate) (string, string) {
	rawComps := components(cert)

	var hashComps []string
	for _, c := range rawComps {
		hashComps = append(hashComps, hash12(c))
	}

	return strings.Join(hashComps, "_"), strings.Join(rawComps, "_")
}

// components produces raw JA4X hash components from a parsed X509 certificate
func components(cert *x509.Certificate) []string {
	var comps []string

	// We can't use Go's RDN functions for issuer and subject because
	// (a) they reorder RDNs and (b) they skip certain empty values.
	// See function ToRDNSequence() in package crypto/x509/pkix for details.
	// Instead we need to parse the raw sequences ourselves.
	for _, raw := range [][]byte{cert.RawIssuer, cert.RawSubject} {
		var rdnSeq pkix.RDNSequence
		var rdnHex []string

		if _, err := asn1.Unmarshal(raw, &rdnSeq); err == nil {
			for _, rdnSet := range rdnSeq {
				for _, rdn := range rdnSet {
					// The JA4X specification uses raw bytes from the ASN.1 body.
					if b := getASN1Body(rdn.Type); b != nil {
						rdnHex = append(rdnHex, hex.EncodeToString(b))
					}
				}
			}
		}

		comps = append(comps, strings.Join(rdnHex, ","))
	}

	// Go stores the extensions in a suitable raw format.
	var extHex []string
	for _, ext := range cert.Extensions {
		if b := getASN1Body(ext.Id); b != nil {
			extHex = append(extHex, hex.EncodeToString(b))
		}
	}

	comps = append(comps, strings.Join(extHex, ","))

	return comps
}

// getASN1Body returns the body of a marshalled ASN.1 sequence, ignoring errors
func getASN1Body(oid asn1.ObjectIdentifier) []byte {

	rawOid, err := asn1.Marshal(oid)
	if err != nil {
		return nil
	}

	// ASN.1 header consists of a Tag byte and Length bytes
	headerLen := 2
	if int(rawOid[1]) > 128 {
		headerLen += int(rawOid[1]) - 128
	}

	return rawOid[headerLen:]
}

// hash12 is the first 12 characters of the SHA256 of a string,
// with the exception that empty strings hash to all zeros instead of e3b0c44298fc.
func hash12(s string) string {

	if s == "" {
		return "000000000000"
	}

	hash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(hash[:])[:12]
}
