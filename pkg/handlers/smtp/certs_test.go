package smtp

import (
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"testing"
)

func TestRandomSerialIsUnique(t *testing.T) {
	const n = 100
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		s := randomSerial()
		if s.Sign() < 0 {
			t.Fatalf("serial %s is negative", s)
		}
		key := s.String()
		if _, dup := seen[key]; dup {
			t.Fatalf("duplicate serial %s after %d draws", key, i)
		}
		seen[key] = struct{}{}
	}
}

func TestRandoCertHasFreshSerial(t *testing.T) {
	a := randoCert()
	b := randoCert()

	if a.SerialNumber == nil || b.SerialNumber == nil {
		t.Fatal("serial number should not be nil")
	}
	if a.SerialNumber.Cmp(b.SerialNumber) == 0 {
		t.Errorf("expected unique serials, both = %s", a.SerialNumber)
	}
	// Guard against the old hardcoded 2019 value sneaking back in.
	if a.SerialNumber.Cmp(big.NewInt(2019)) == 0 {
		t.Error("serial should not be the legacy hardcoded 2019")
	}
}

func TestRandoCACertFlags(t *testing.T) {
	ca := randoCACert()
	if !ca.IsCA {
		t.Error("CA cert should have IsCA=true")
	}
	if !ca.BasicConstraintsValid {
		t.Error("CA cert should have BasicConstraintsValid=true")
	}
	if ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("CA cert should have KeyUsageCertSign")
	}
}

func TestRandoDNSCertSANs(t *testing.T) {
	cert := randoDNSCert([]string{"foo.example", "bar.example"})
	if len(cert.DNSNames) != 2 {
		t.Fatalf("DNSNames length = %d, want 2", len(cert.DNSNames))
	}
	if cert.DNSNames[0] != "foo.example" || cert.DNSNames[1] != "bar.example" {
		t.Errorf("DNSNames = %v, want [foo.example bar.example]", cert.DNSNames)
	}
}

func TestInsecureCertPrivateKeyMemoised(t *testing.T) {
	ic := NewInsecureCert()
	first := ic.PrivateKey()
	second := ic.PrivateKey()
	if first != second {
		t.Error("PrivateKey() should return the same instance on subsequent calls")
	}
}

func TestInsecureCertCACertCached(t *testing.T) {
	ic := NewInsecureCert()
	first := ic.CACert()
	second := ic.CACert()
	if first != second {
		t.Error("CACert() should be cached and return the same pointer")
	}
}

func TestInsecureCertDNSCertCacheKey(t *testing.T) {
	ic := NewInsecureCert()
	c1 := ic.DNSCert("a.example", "b.example")
	c2 := ic.DNSCert("a.example", "b.example")
	c3 := ic.DNSCert("c.example")

	if c1 != c2 {
		t.Error("identical DNS names should hit the cache")
	}
	if c1 == c3 {
		t.Error("different DNS names should produce different cert entries")
	}
}

func TestInsecureCertAuthorityMemoised(t *testing.T) {
	ic := NewInsecureCert()
	a1 := ic.Authority()
	a2 := ic.Authority()
	if a1 != a2 {
		t.Error("Authority() should return the same instance on subsequent calls")
	}
}

func TestInsecureCertCABytesParseable(t *testing.T) {
	ic := NewInsecureCert()
	caBytes, err := ic.CABytes()
	if err != nil {
		t.Fatalf("CABytes: %v", err)
	}
	cert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if !cert.IsCA {
		t.Error("parsed CA cert should report IsCA=true")
	}
}

func TestInsecureCertSignedDNSPEMRoundTrip(t *testing.T) {
	ic := NewInsecureCert()
	certPEM, keyPEM, err := ic.SignedDNSPEM("svc.example")
	if err != nil {
		t.Fatalf("SignedDNSPEM: %v", err)
	}

	certBlock, _ := pem.Decode(certPEM.Bytes())
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		t.Fatalf("expected CERTIFICATE PEM block, got %+v", certBlock)
	}
	if _, err := x509.ParseCertificate(certBlock.Bytes); err != nil {
		t.Fatalf("parse signed cert: %v", err)
	}

	keyBlock, _ := pem.Decode(keyPEM.Bytes())
	if keyBlock == nil || keyBlock.Type != "RSA PRIVATE KEY" {
		t.Fatalf("expected RSA PRIVATE KEY PEM block, got %+v", keyBlock)
	}
	if _, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes); err != nil {
		t.Fatalf("parse signed key: %v", err)
	}
}

func TestInsecureCertSignedDNSCertCached(t *testing.T) {
	ic := NewInsecureCert()
	first, err := ic.SignedDNSCert("svc.example")
	if err != nil {
		t.Fatalf("first SignedDNSCert: %v", err)
	}
	second, err := ic.SignedDNSCert("svc.example")
	if err != nil {
		t.Fatalf("second SignedDNSCert: %v", err)
	}
	if &first[0] != &second[0] {
		t.Error("repeated SignedDNSCert for the same name should return cached bytes")
	}
}

func TestInsecureCertTLSConfig(t *testing.T) {
	ic := NewInsecureCert()
	cfg, err := ic.TLSConfig("svc.example")
	if err != nil {
		t.Fatalf("TLSConfig: %v", err)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("Certificates len = %d, want 1", len(cfg.Certificates))
	}
	if len(cfg.Certificates[0].Certificate) == 0 {
		t.Error("certificate chain should not be empty")
	}

	// Ensure the returned config is usable for a TLS handshake setup.
	var _ = cfg
}
