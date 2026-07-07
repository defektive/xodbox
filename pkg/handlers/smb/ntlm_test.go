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
	if _, err := parseAuthenticate(buildChallenge(defaultTargetName)); err == nil {
		t.Error("expected error parsing a CHALLENGE as an AUTHENTICATE")
	}
}

func TestBuildChallengeIsWellFormed(t *testing.T) {
	ch := buildChallenge(defaultTargetName)
	if ntlmMessageType(ch) != ntlmChallenge {
		t.Fatalf("message type = %d, want %d", ntlmMessageType(ch), ntlmChallenge)
	}
	// ServerChallenge lives at offset 24 and must be the fixed value we
	// later echo into captured hashes.
	if got := ch[24:32]; !bytes.Equal(got, ServerChallenge) {
		t.Errorf("server challenge in message = %x, want %x", got, ServerChallenge)
	}
}

// TestBuildChallengePayloadOffsets guards the bug where the declared
// TargetName/TargetInfo buffer offsets did not account for the 8-byte
// Version field, making clients read past the buffer
// (NT_STATUS_BUFFER_TOO_SMALL). It resolves the payloads via the field
// descriptors exactly as a client would.
func TestBuildChallengePayloadOffsets(t *testing.T) {
	// Use a custom target name to also prove it flows through into the
	// advertised AV pairs (configurable to avoid fingerprinting).
	const customName = "CORP-FS01"
	ch := buildChallenge(customName)

	// TargetNameFields @12 must resolve to the configured target name.
	if got := fromUTF16le(field(ch, 12)); got != customName {
		t.Errorf("TargetName via declared offset = %q, want %q", got, customName)
	}

	// TargetInfoFields @40 must resolve to a well-formed AV_PAIR list that
	// stays in bounds and ends with MsvAvEOL.
	info := field(ch, 40)
	if info == nil {
		t.Fatal("TargetInfo did not resolve within the message buffer")
	}
	sawEOL := false
	for i := 0; i+4 <= len(info); {
		id := binary.LittleEndian.Uint16(info[i:])
		ln := int(binary.LittleEndian.Uint16(info[i+2:]))
		i += 4 + ln
		if i > len(info) {
			t.Fatalf("AV_PAIR id %d length %d overruns TargetInfo", id, ln)
		}
		if id == msvAvEOL {
			sawEOL = true
			break
		}
	}
	if !sawEOL {
		t.Error("TargetInfo did not terminate with MsvAvEOL")
	}
}

func TestNegotiateResponseAdvertisesDialect(t *testing.T) {
	resp := buildNegotiateResponse(0, dialect0210)
	// DialectRevision sits at body offset 4, and the body follows the
	// 64-byte SMB2 header.
	got := binary.LittleEndian.Uint16(resp[64+4:])
	if got != dialect0210 {
		t.Errorf("advertised dialect = %#04x, want %#04x (SMB 2.1)", got, dialect0210)
	}
	if smb2Command(resp) != cmdNegotiate {
		t.Errorf("response command = %#x, want NEGOTIATE", smb2Command(resp))
	}
}

// negotiateRequest builds a minimal SMB2 NEGOTIATE request advertising the
// given dialects so selectDialect can be exercised.
func negotiateRequest(dialects ...uint16) []byte {
	body := make([]byte, 36)
	binary.LittleEndian.PutUint16(body[0:], 36) // StructureSize
	binary.LittleEndian.PutUint16(body[2:], uint16(len(dialects)))
	for _, d := range dialects {
		var b [2]byte
		binary.LittleEndian.PutUint16(b[:], d)
		body = append(body, b[:]...)
	}
	h := make([]byte, 64)
	copy(h[0:4], smb2Magic)
	binary.LittleEndian.PutUint16(h[12:], cmdNegotiate)
	return append(h, body...)
}

func TestSelectDialect(t *testing.T) {
	cases := []struct {
		name    string
		offered []uint16
		want    uint16
	}{
		{"pinned to 2.0.2", []uint16{dialect0202}, dialect0202},
		{"multi-dialect prefers 2.1", []uint16{0x0202, 0x0210, 0x0300, 0x0311}, dialect0210},
		{"only 2.1", []uint16{dialect0210}, dialect0210},
		{"only unsupported falls back", []uint16{0x0300, 0x0311}, dialect0210},
		{"empty request falls back", nil, dialect0210},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := selectDialect(negotiateRequest(tc.offered...))
			if got != tc.want {
				t.Errorf("selectDialect(%v) = %#04x, want %#04x", tc.offered, got, tc.want)
			}
		})
	}
}

func TestSelectDialectShortRequest(t *testing.T) {
	// A header with no body must not panic and should fall back.
	if got := selectDialect(make([]byte, 64)); got != dialect0210 {
		t.Errorf("selectDialect(short) = %#04x, want fallback %#04x", got, dialect0210)
	}
}

func TestFindNTLMSSPInSPNEGO(t *testing.T) {
	challenge := buildChallenge(defaultTargetName)
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
