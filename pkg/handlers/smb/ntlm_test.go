package smb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

// buildAuthenticate assembles a minimal NTLMSSP AUTHENTICATE (type 3)
// message with the given domain, user, and NT challenge response so the
// parser can be exercised without a live client.
func buildAuthenticate(domain, user string, ntResponse []byte) []byte {
	dom := utf16le(domain)
	usr := utf16le(user)

	const headerLen = 64
	ntOff := headerLen
	domOff := ntOff + len(ntResponse)
	usrOff := domOff + len(dom)

	buf := make([]byte, headerLen)
	copy(buf[0:], ntlmSignature)
	binary.LittleEndian.PutUint32(buf[8:], ntlmAuthenticate)
	// LmChallengeResponse fields @12 left zero.
	// NtChallengeResponse fields @20.
	binary.LittleEndian.PutUint16(buf[20:], uint16(len(ntResponse)))
	binary.LittleEndian.PutUint16(buf[22:], uint16(len(ntResponse)))
	binary.LittleEndian.PutUint32(buf[24:], uint32(ntOff))
	// DomainName fields @28.
	binary.LittleEndian.PutUint16(buf[28:], uint16(len(dom)))
	binary.LittleEndian.PutUint16(buf[30:], uint16(len(dom)))
	binary.LittleEndian.PutUint32(buf[32:], uint32(domOff))
	// UserName fields @36.
	binary.LittleEndian.PutUint16(buf[36:], uint16(len(usr)))
	binary.LittleEndian.PutUint16(buf[38:], uint16(len(usr)))
	binary.LittleEndian.PutUint32(buf[40:], uint32(usrOff))
	binary.LittleEndian.PutUint32(buf[60:], negotiateUnicode)

	buf = append(buf, ntResponse...)
	buf = append(buf, dom...)
	buf = append(buf, usr...)
	return buf
}

func TestParseAuthenticateAndHashcatLine(t *testing.T) {
	// 16-byte NTProofStr followed by a client blob of arbitrary length.
	ntProof := bytes.Repeat([]byte{0xAB}, 16)
	blob := []byte{0x01, 0x01, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef}
	nt := append(append([]byte{}, ntProof...), blob...)

	msg := buildAuthenticate("CORP", "alice", nt)

	info, err := parseAuthenticate(msg)
	if err != nil {
		t.Fatalf("parseAuthenticate: %v", err)
	}
	if info.User != "alice" {
		t.Errorf("User = %q, want alice", info.User)
	}
	if info.Domain != "CORP" {
		t.Errorf("Domain = %q, want CORP", info.Domain)
	}
	if info.Account() != "CORP\\alice" {
		t.Errorf("Account = %q, want CORP\\alice", info.Account())
	}

	want := fmt.Sprintf("alice::CORP:%x:%x:%x", ServerChallenge, ntProof, blob)
	if got := info.HashcatLine(); got != want {
		t.Errorf("HashcatLine =\n  %s\nwant\n  %s", got, want)
	}
}

func TestHashcatLineIsCrackFormat(t *testing.T) {
	nt := bytes.Repeat([]byte{0x11}, 40)
	msg := buildAuthenticate("", "bob", nt)
	info, err := parseAuthenticate(msg)
	if err != nil {
		t.Fatalf("parseAuthenticate: %v", err)
	}
	// hashcat mode 5600 has exactly 5 colon-separated fields after user::.
	parts := strings.Split(info.HashcatLine(), ":")
	if len(parts) != 6 { // user, "", domain, chal, proof, blob
		t.Errorf("expected 6 colon fields, got %d: %q", len(parts), info.HashcatLine())
	}
	if info.Account() != "bob" {
		t.Errorf("Account with empty domain = %q, want bob", info.Account())
	}
}

func TestParseAuthenticateRejectsShortNT(t *testing.T) {
	// LM-style / truncated NT response (< 16 bytes) must be rejected.
	msg := buildAuthenticate("CORP", "alice", []byte{0x01, 0x02, 0x03})
	if _, err := parseAuthenticate(msg); err == nil {
		t.Error("expected error for truncated NtChallengeResponse")
	}
}

func TestParseAuthenticateRejectsWrongType(t *testing.T) {
	if _, err := parseAuthenticate(buildChallenge()); err == nil {
		t.Error("expected error parsing a CHALLENGE as an AUTHENTICATE")
	}
}

func TestBuildChallengeIsWellFormed(t *testing.T) {
	ch := buildChallenge()
	if ntlmMessageType(ch) != ntlmChallenge {
		t.Fatalf("message type = %d, want %d", ntlmMessageType(ch), ntlmChallenge)
	}
	// ServerChallenge lives at offset 24 and must be the fixed value we
	// later echo into captured hashes.
	if got := ch[24:32]; !bytes.Equal(got, ServerChallenge) {
		t.Errorf("server challenge in message = %x, want %x", got, ServerChallenge)
	}
}

func TestFindNTLMSSPInSPNEGO(t *testing.T) {
	challenge := buildChallenge()
	wrapped := buildNegTokenResp(challenge)
	found := findNTLMSSP(wrapped)
	if !bytes.Equal(found, challenge) {
		t.Errorf("findNTLMSSP did not recover the embedded token")
	}
	if findNTLMSSP([]byte("no token here")) != nil {
		t.Error("findNTLMSSP should return nil when no signature present")
	}
}

func TestUTF16RoundTrip(t *testing.T) {
	for _, s := range []string{"alice", "CORP", "wörk", ""} {
		if got := fromUTF16le(utf16le(s)); got != s {
			t.Errorf("utf16 round-trip %q = %q", s, got)
		}
	}
}
