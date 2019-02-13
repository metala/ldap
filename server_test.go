package ldap

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"
)

var timeout = 400 * time.Millisecond
var serverBaseDN = "o=testers,c=test"

type selfSignedCert struct {
	// Path to the SSL certificates.
	CACertPath, CertPath string

	// Path to the private keys for the SSL certificates.
	CAKeyPath, KeyPath string
}

func newSelfSignedCert() *selfSignedCert {
	capk, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}

	caSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}

	caTemplate := x509.Certificate{
		SerialNumber: caSerial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(7 * 24 * time.Hour),

		KeyUsage:    x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		BasicConstraintsValid: true,

		Subject: pkix.Name{
			Organization: []string{"my_test_ca"},
			CommonName:   "My Test CA",
		},

		IsCA: true,
	}

	caCert, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, capk.Public(), capk)
	if err != nil {
		panic(err)
	}
	// fmt.Printf("CA CERT\n%#v\n", caCert)
	caCertPEM := &pem.Block{Type: "CERTIFICATE", Bytes: caCert}
	caCertFile, err := ioutil.TempFile("", "cacert-*.pem")
	if err != nil {
		panic(err)
	}
	if err := pem.Encode(caCertFile, caCertPEM); err != nil {
		panic(err)
	}
	caCertFile.Close()

	caKeyFile, err := ioutil.TempFile("", "cakey-*.pem")
	if err != nil {
		panic(err)
	}
	if err := pem.Encode(caKeyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(capk)}); err != nil {
		panic(err)
	}
	caKeyFile.Close()

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}
	// Basically the same as the CA template, but its own serial, and with ip addresses and dns names.
	template := x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(7 * 24 * time.Hour),

		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		BasicConstraintsValid: true,

		Subject: pkix.Name{
			CommonName: "localhost",
		},

		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:    []string{"localhost"},
	}

	pk, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	cert, err := x509.CreateCertificate(rand.Reader, &template, &caTemplate, pk.Public(), capk)
	if err != nil {
		panic(err)
	}
	certPEM := &pem.Block{Type: "CERTIFICATE", Bytes: cert}
	certFile, err := ioutil.TempFile("", "sslcert-*.pem")
	if err != nil {
		panic(err)
	}
	if err := pem.Encode(certFile, certPEM); err != nil {
		panic(err)
	}
	certFile.Close()

	keyFile, err := ioutil.TempFile("", "key-*.pem")
	if err != nil {
		panic(err)
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(pk)}); err != nil {
		panic(err)
	}
	keyFile.Close()

	return &selfSignedCert{
		CACertPath: caCertFile.Name(),
		CAKeyPath:  caKeyFile.Name(),
		CertPath:   certFile.Name(),
		KeyPath:    keyFile.Name(),
	}
}

func (c *selfSignedCert) cleanup() {
	os.RemoveAll(c.CertPath)
	os.RemoveAll(c.CACertPath)
	os.RemoveAll(c.KeyPath)
	os.RemoveAll(c.CAKeyPath)
}

func (c *selfSignedCert) ClientTLSConfig() *tls.Config {
	cert, err := ioutil.ReadFile(c.CACertPath)
	if err != nil {
		panic(err)
	}

	// Return a TLS config that trusts our self-generated CA.
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cert) {
		panic("failed to append certificate")
	}
	return &tls.Config{
		RootCAs: pool,
	}
}

func (c *selfSignedCert) ServerTLSConfig() *tls.Config {
	cert, err := tls.LoadX509KeyPair(c.CertPath, c.KeyPath)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		ServerName:   "localhost",
		Certificates: []tls.Certificate{cert},
	}
}

func TestStartTLS(t *testing.T) {
	if runtime.GOOS == "darwin" {
		defer func() {
			if t.Failed() {
				t.Logf(`NOTE: this test won't pass with the built-in Mac ldap utilities.
Work around this by using brew install openldap, and running the test as PATH=/usr/local/opt/openldap/bin:$PATH go test.

This test uses environment variables that are respected by OpenLDAP, but the Mac utilities don't let you override
security settings through environment variables; they expect certificates to be added to the system keychain,
which is very heavy-handed for a test like this.
`)
			}
		}()
	}
	cert := newSelfSignedCert()
	defer cert.cleanup()

	s := NewServer()
	defer s.Close()
	s.Bind = BindAnonOK
	s.Search = SearchSimple
	s.TLSConfig = cert.ServerTLSConfig()

	ln, addr := mustListen()
	go func() {
		if err := s.Serve(ln); err != nil {
			t.Errorf("s.Serve failed: %s", err.Error())
		}
	}()

	done := make(chan struct{})
	go func() {
		cmd := exec.Command("env",
			"LDAPTLS_CACERT="+cert.CACertPath,
			"ldapsearch", "-H", "ldap://"+addr, "-ZZ", "-d", "-1", "-x", "-b", "o=testers,c=test")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Error(err)
		}

		if !strings.Contains(string(out), "# numEntries: 3") || !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("search did not succeed:\n%s", out)
		}

		close(done)
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Error("ldapsearch command timed out")
	}
}

/////////////////////////
func TestBindAnonOK(t *testing.T) {
	done := make(chan bool)
	s := NewServer()
	defer s.Close()
	ln, addr := mustListen()
	go func() {
		s.Bind = BindAnonOK
		if err := s.Serve(ln); err != nil {
			t.Errorf("s.Serve failed: %s", err.Error())
		}
	}()

	go func() {
		cmd := exec.Command("ldapsearch", "-H", "ldap://"+addr, "-x", "-b", "o=testers,c=test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
}

/////////////////////////
func TestBindAnonFail(t *testing.T) {
	done := make(chan bool)
	s := NewServer()
	defer s.Close()
	ln, addr := mustListen()
	go func() {
		if err := s.Serve(ln); err != nil {
			t.Errorf("s.Serve failed: %s", err.Error())
		}
	}()

	time.Sleep(timeout)
	go func() {
		cmd := exec.Command("ldapsearch", "-H", "ldap://"+addr, "-x", "-b", "o=testers,c=test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_bind: Invalid credentials (49)") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
}

/////////////////////////
func TestBindSimpleOK(t *testing.T) {
	done := make(chan bool)
	s := NewServer()
	defer s.Close()
	ln, addr := mustListen()
	go func() {
		s.Search = SearchSimple
		s.Bind = BindSimple
		if err := s.Serve(ln); err != nil {
			t.Errorf("s.Serve failed: %s", err.Error())
		}
	}()

	serverBaseDN := "o=testers,c=test"

	go func() {
		cmd := exec.Command("ldapsearch", "-H", "ldap://"+addr, "-x",
			"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
}

/////////////////////////
func TestBindSimpleFailBadPw(t *testing.T) {
	done := make(chan bool)
	s := NewServer()
	defer s.Close()
	ln, addr := mustListen()
	go func() {
		s.Bind = BindSimple
		if err := s.Serve(ln); err != nil {
			t.Errorf("s.Serve failed: %s", err.Error())
		}
	}()

	serverBaseDN := "o=testers,c=test"

	go func() {
		cmd := exec.Command("ldapsearch", "-H", "ldap://"+addr, "-x",
			"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "BADPassword")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_bind: Invalid credentials (49)") {
			t.Errorf("ldapsearch succeeded - should have failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
}

/////////////////////////
func TestBindSimpleFailBadDn(t *testing.T) {
	done := make(chan bool)
	s := NewServer()
	defer s.Close()
	ln, addr := mustListen()
	go func() {
		s.Bind = BindSimple
		if err := s.Serve(ln); err != nil {
			t.Errorf("s.Serve failed: %s", err.Error())
		}
	}()

	serverBaseDN := "o=testers,c=test"

	go func() {
		cmd := exec.Command("ldapsearch", "-H", "ldap://"+addr, "-x",
			"-b", serverBaseDN, "-D", "cn=testoy,"+serverBaseDN, "-w", "iLike2test")
		out, _ := cmd.CombinedOutput()
		if string(out) != "ldap_bind: Invalid credentials (49)\n" {
			t.Errorf("ldapsearch succeeded - should have failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
}

/////////////////////////
func TestBindSSL(t *testing.T) {
	t.Skip("unclear how to configure ldapsearch command to trust or skip verification of a custom SSL cert")
	longerTimeout := 300 * time.Millisecond
	done := make(chan bool)
	s := NewServer()
	defer s.Close()

	cert, err := tls.LoadX509KeyPair("tests/cert_DONOTUSE.pem", "tests/key_DONOTUSE.pem")
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := tls.Config{Certificates: []tls.Certificate{cert}}
	tlsConfig.ServerName = "localhost"
	ln, err := tls.Listen("tcp", "localhost:0", &tlsConfig)
	if err != nil {
		t.Fatal(err)
	}

	ldapURLSSL := "ldaps://" + ln.Addr().String()

	go func() {
		s.Bind = BindAnonOK
		if err := s.Serve(ln); err != nil {
			t.Errorf("s.Serve failed: %s", err.Error())
		}
	}()

	go func() {
		time.Sleep(longerTimeout)
		cmd := exec.Command("ldapsearch", "-H", ldapURLSSL, "-x", "-b", "o=testers,c=test")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Error(err)
			return
		}
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(longerTimeout * 2):
		t.Errorf("ldapsearch command timed out")
	}
}

/////////////////////////
func TestBindPanic(t *testing.T) {
	done := make(chan bool)
	s := NewServer()
	defer s.Close()
	ln, addr := mustListen()
	go func() {
		s.Bind = BindPanic
		if err := s.Serve(ln); err != nil {
			t.Errorf("s.Serve failed: %s", err.Error())
		}
	}()

	go func() {
		cmd := exec.Command("ldapsearch", "-H", "ldap://"+addr, "-x", "-b", "o=testers,c=test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_bind: Operations error") {
			t.Errorf("ldapsearch should have returned operations error due to panic: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
}

/////////////////////////
type testStatsWriter struct {
	buffer *bytes.Buffer
}

func (tsw testStatsWriter) Write(buf []byte) (int, error) {
	tsw.buffer.Write(buf)
	return len(buf), nil
}

func TestSearchStats(t *testing.T) {
	w := testStatsWriter{&bytes.Buffer{}}
	log.SetOutput(w)

	done := make(chan bool)
	s := NewServer()
	defer s.Close()
	ln, addr := mustListen()

	go func() {
		s.Search = SearchSimple
		s.Bind = BindAnonOK
		s.SetStats(true)
		if err := s.Serve(ln); err != nil {
			t.Errorf("s.Serve failed: %s", err.Error())
		}
	}()

	go func() {
		cmd := exec.Command("ldapsearch", "-H", "ldap://"+addr, "-x", "-b", "o=testers,c=test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}

	stats := s.GetStats()
	log.Println(stats)
	if stats.Conns != 1 || stats.Binds != 1 {
		t.Errorf("Stats data missing or incorrect: %v", w.buffer.String())
	}
}

func BindAnonOK(bindDN, bindSimplePw string, conn net.Conn) (LDAPResultCode, error) {
	if bindDN == "" && bindSimplePw == "" {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInvalidCredentials, nil
}

func BindSimple(bindDN, bindSimplePw string, conn net.Conn) (LDAPResultCode, error) {
	if bindDN == "cn=testy,o=testers,c=test" && bindSimplePw == "iLike2test" {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInvalidCredentials, nil
}

func BindPanic(bindDN, bindSimplePw string, conn net.Conn) (LDAPResultCode, error) {
	panic("test panic at the disco")
}

func SearchSimple(boundDN string, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	entries := []*Entry{
		&Entry{"cn=ned,o=testers,c=test", []*EntryAttribute{
			&EntryAttribute{"cn", []string{"ned"}},
			&EntryAttribute{"o", []string{"ate"}},
			&EntryAttribute{"uidNumber", []string{"5000"}},
			&EntryAttribute{"accountstatus", []string{"active"}},
			&EntryAttribute{"uid", []string{"ned"}},
			&EntryAttribute{"description", []string{"ned via sa"}},
			&EntryAttribute{"objectclass", []string{"posixaccount"}},
		}},
		&Entry{"cn=trent,o=testers,c=test", []*EntryAttribute{
			&EntryAttribute{"cn", []string{"trent"}},
			&EntryAttribute{"o", []string{"ate"}},
			&EntryAttribute{"uidNumber", []string{"5005"}},
			&EntryAttribute{"accountstatus", []string{"active"}},
			&EntryAttribute{"uid", []string{"trent"}},
			&EntryAttribute{"description", []string{"trent via sa"}},
			&EntryAttribute{"objectclass", []string{"posixaccount"}},
		}},
		&Entry{"cn=randy,o=testers,c=test", []*EntryAttribute{
			&EntryAttribute{"cn", []string{"randy"}},
			&EntryAttribute{"o", []string{"ate"}},
			&EntryAttribute{"uidNumber", []string{"5555"}},
			&EntryAttribute{"accountstatus", []string{"active"}},
			&EntryAttribute{"uid", []string{"randy"}},
			&EntryAttribute{"objectclass", []string{"posixaccount"}},
		}},
	}
	return ServerSearchResult{entries, []string{}, []Control{}, LDAPResultSuccess}, nil
}

func SearchPanic(boundDN string, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	panic("this is a test panic")
}

func SearchControls(boundDN string, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	entries := []*Entry{}
	if len(searchReq.Controls) == 1 && searchReq.Controls[0].GetControlType() == "1.2.3.4.5" {
		newEntry := &Entry{"cn=hamburger,o=testers,c=testz", []*EntryAttribute{
			&EntryAttribute{"cn", []string{"hamburger"}},
			&EntryAttribute{"o", []string{"testers"}},
			&EntryAttribute{"uidNumber", []string{"5000"}},
			&EntryAttribute{"accountstatus", []string{"active"}},
			&EntryAttribute{"uid", []string{"hamburger"}},
			&EntryAttribute{"objectclass", []string{"posixaccount"}},
		}}
		entries = append(entries, newEntry)
	}
	return ServerSearchResult{entries, []string{}, []Control{}, LDAPResultSuccess}, nil
}

// mustListen returns a net.Listener listening on a random port.
func mustListen() (ln net.Listener, actualAddr string) {
	ln, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		panic(err)
	}

	return ln, ln.Addr().String()
}
