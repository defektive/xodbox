package smtp

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"strings"
	"time"
)

func randoCert() *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature,
	}
}

func randoCACert() *x509.Certificate {
	caCert := randoCert()

	caCert.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
	caCert.IsCA = true
	caCert.BasicConstraintsValid = true
	return caCert
}

func randoDNSCert(subject []string) *x509.Certificate {
	subjectCert := randoCert()

	//subjectCert.IPAddresses = []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	//subjectCert.SubjectKeyId = []byte{1, 2, 3, 4, 6}
	subjectCert.DNSNames = subject
	return subjectCert
}

type InsecureCert struct {
	privateKey  *rsa.PrivateKey
	caCert      *x509.Certificate
	randoCerts  map[string]*x509.Certificate
	randoSigned map[string][]byte
	authority   *InsecureCert
}

func NewInsecureCert() *InsecureCert {
	return &InsecureCert{
		randoCerts:  make(map[string]*x509.Certificate),
		randoSigned: make(map[string][]byte),
	}
}

func (i *InsecureCert) PrivateKey() *rsa.PrivateKey {
	if i.privateKey == nil {
		var err error
		i.privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			lg().Error("Error generating private key", "err", err)
		}
	}
	return i.privateKey
}

func certLookupKey(certType, certName string) string {
	return fmt.Sprintf("%s:%s", certType, certName)
}

func (i *InsecureCert) CACert() *x509.Certificate {
	var certKey = certLookupKey("CA", "main")
	if _, ok := i.randoCerts[certKey]; !ok {
		i.randoCerts[certKey] = randoCACert()
	}

	return i.randoCerts[certKey]
}

func (i *InsecureCert) CABytes() ([]byte, error) {
	ca := i.CACert()

	// create the CA
	return x509.CreateCertificate(rand.Reader, ca, ca, i.PrivateKey().PublicKey, i.PrivateKey())
}

func (i *InsecureCert) DNSCert(dnsNames ...string) *x509.Certificate {

	var certKey = certLookupKey("DNS", strings.Join(dnsNames, ","))
	if _, ok := i.randoCerts[certKey]; !ok {
		i.randoCerts[certKey] = randoDNSCert(dnsNames)
	}

	return i.randoCerts[certKey]
}

func (i *InsecureCert) Authority() *InsecureCert {

	if i.authority == nil {
		i.authority = NewInsecureCert()
	}
	return i.authority
}

func (i *InsecureCert) SignedDNSCert(dnsNames ...string) ([]byte, error) {

	var certKey = certLookupKey("DNS", strings.Join(dnsNames, ","))
	if _, ok := i.randoSigned[certKey]; !ok {

		insecureCA := i.Authority()
		certPrivKey := i.PrivateKey()
		cert := i.DNSCert("pizza.com")

		var err error

		i.randoSigned[certKey], err = x509.CreateCertificate(rand.Reader, cert, insecureCA.CACert(), &certPrivKey.PublicKey, insecureCA.PrivateKey())
		if err != nil {
			return nil, err
		}
	}

	return i.randoSigned[certKey], nil
}

func (i *InsecureCert) SignedDNSPEM(dnsNames ...string) (*bytes.Buffer, *bytes.Buffer, error) {

	certBytes, err := i.SignedDNSCert(dnsNames...)
	if err != nil {
		return nil, nil, err
	}

	var certPEM = new(bytes.Buffer)
	if err := pem.Encode(certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
		return nil, nil, err
	}

	var certPrivKeyPEM = new(bytes.Buffer)
	if err := pem.Encode(certPrivKeyPEM, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(i.PrivateKey())}); err != nil {

	}

	return certPEM, certPrivKeyPEM, nil
}

func (i *InsecureCert) TLSConfig(dnsNames ...string) (*tls.Config, error) {

	certPem, keyPem, err := i.SignedDNSPEM(dnsNames...)
	if err != nil {
		return nil, err
	}

	cer, err := tls.X509KeyPair(certPem.Bytes(), keyPem.Bytes())
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cer},
	}, nil

}

func certsetup() (certPEM *bytes.Buffer, certPrivKeyPEM *bytes.Buffer, err error) {
	// set up our CA certificate
	// TODO: Randomize this :D
	log.Println("Creating Certificates...")

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// create our private and public key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	// create the CA
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	// pem encode
	caPEM := new(bytes.Buffer)
	if err := pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	}); err != nil {
		return nil, nil, err
	}

	caPrivKeyPEM := new(bytes.Buffer)
	if err := pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	}); err != nil {
		return nil, nil, err
	}

	// set up our server certificate
	// TODO: Randomize this :D
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	certPEM = new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM = new(bytes.Buffer)
	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	return
}
