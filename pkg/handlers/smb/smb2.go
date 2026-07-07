package smb

import (
	"encoding/binary"
	"errors"
	"io"
)

// Protocol magics.
var (
	smb1Magic = []byte{0xff, 'S', 'M', 'B'}
	smb2Magic = []byte{0xfe, 'S', 'M', 'B'}
)

// SMB2 commands we care about.
const (
	cmdNegotiate    = 0x0000
	cmdSessionSetup = 0x0001
)

// NT status codes.
const (
	statusSuccess            = 0x00000000
	statusMoreProcessingReqd = 0xC0000016
	statusLogonFailure       = 0xC000006D
)

// Dialects. The wildcard is returned when a client reaches us via a
// legacy SMB1 multi-protocol negotiate, prompting it to re-negotiate over
// SMB2; 0x0202 (SMB 2.0.2) is the plain dialect we settle on afterwards.
const (
	dialectWildcard = 0x02FF
	dialect0202     = 0x0202
)

// sessionID is a fixed non-zero session id handed out to every client.
// A single fake session per connection is all the capture flow needs.
const sessionID = 0x0000000000001234

// serverGUID is a constant identity for the fake server. The value is
// cosmetic — clients only echo it — so a fixed GUID avoids pulling in a
// randomness source.
var serverGUID = []byte{
	0x78, 0x6f, 0x64, 0x62, 0x6f, 0x78, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
}

// maxNetBIOSMessage caps a single inbound SMB message to guard against a
// hostile length prefix. 16 MiB comfortably exceeds any real negotiate or
// session-setup packet.
const maxNetBIOSMessage = 16 << 20

// readPacket reads one NetBIOS-framed SMB message: a 4-byte header whose
// low 24 bits are the big-endian payload length, followed by the payload.
func readPacket(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	// hdr[0] is the NetBIOS message type (0x00 = session message).
	length := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if length == 0 {
		return []byte{}, nil
	}
	if length > maxNetBIOSMessage {
		return nil, errors.New("smb: NetBIOS message too large")
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// writePacket frames msg with a NetBIOS session header and writes it.
func writePacket(w io.Writer, msg []byte) error {
	n := len(msg)
	hdr := []byte{0x00, lowByte(n >> 16), lowByte(n >> 8), lowByte(n)}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(msg)
	return err
}

// isSMB1 / isSMB2 classify a raw SMB message by its 4-byte protocol id.
func isSMB1(msg []byte) bool { return len(msg) >= 4 && string(msg[:4]) == string(smb1Magic) }
func isSMB2(msg []byte) bool { return len(msg) >= 4 && string(msg[:4]) == string(smb2Magic) }

// smb2Command returns the Command field of an SMB2 message.
func smb2Command(msg []byte) uint16 {
	if len(msg) < 14 {
		return 0xffff
	}
	return binary.LittleEndian.Uint16(msg[12:])
}

// smb2MessageID returns the MessageId field of an SMB2 message.
func smb2MessageID(msg []byte) uint64 {
	if len(msg) < 32 {
		return 0
	}
	return binary.LittleEndian.Uint64(msg[24:])
}

// smb2Header builds a 64-byte SMB2 sync response header.
func smb2Header(command uint16, status uint32, messageID, session uint64) []byte {
	h := make([]byte, 64)
	copy(h[0:4], smb2Magic)
	binary.LittleEndian.PutUint16(h[4:], 64) // StructureSize
	binary.LittleEndian.PutUint32(h[8:], status)
	binary.LittleEndian.PutUint16(h[12:], command)
	binary.LittleEndian.PutUint16(h[14:], 1)          // CreditResponse
	binary.LittleEndian.PutUint32(h[16:], 0x00000001) // SMB2_FLAGS_SERVER_TO_REDIR
	binary.LittleEndian.PutUint64(h[24:], messageID)
	binary.LittleEndian.PutUint64(h[40:], session)
	return h
}

// buildNegotiateResponse builds an SMB2 NEGOTIATE response for the given
// dialect, embedding a SPNEGO negTokenInit that offers NTLMSSP so the
// client proceeds straight to NTLM authentication.
func buildNegotiateResponse(messageID uint64, dialect uint16) []byte {
	secBuf := buildNegTokenInit()

	body := make([]byte, 64)
	binary.LittleEndian.PutUint16(body[0:], 65)      // StructureSize (odd: variable buffer)
	binary.LittleEndian.PutUint16(body[2:], 0x0001)  // SecurityMode: signing enabled
	binary.LittleEndian.PutUint16(body[4:], dialect) // DialectRevision
	copy(body[8:24], serverGUID)
	binary.LittleEndian.PutUint32(body[28:], 0x00100000) // MaxTransactSize
	binary.LittleEndian.PutUint32(body[32:], 0x00100000) // MaxReadSize
	binary.LittleEndian.PutUint32(body[36:], 0x00100000) // MaxWriteSize
	secOff := uint16(64 + 64)                            // header + fixed body
	binary.LittleEndian.PutUint16(body[56:], secOff)     // SecurityBufferOffset
	binary.LittleEndian.PutUint16(body[58:], u16(len(secBuf)))

	out := smb2Header(cmdNegotiate, statusSuccess, messageID, 0)
	out = append(out, body...)
	out = append(out, secBuf...)
	return out
}

// buildSessionSetupResponse builds an SMB2 SESSION_SETUP response with the
// given status and security buffer (typically the NTLMSSP CHALLENGE token
// wrapped in SPNEGO).
func buildSessionSetupResponse(messageID uint64, status uint32, secBuf []byte) []byte {
	body := make([]byte, 8)
	binary.LittleEndian.PutUint16(body[0:], 9) // StructureSize (odd: variable buffer)
	binary.LittleEndian.PutUint16(body[2:], 0) // SessionFlags
	secOff := uint16(64 + 8)                   // header + fixed body
	binary.LittleEndian.PutUint16(body[4:], secOff)
	binary.LittleEndian.PutUint16(body[6:], u16(len(secBuf)))

	out := smb2Header(cmdSessionSetup, status, messageID, sessionID)
	out = append(out, body...)
	out = append(out, secBuf...)
	return out
}

// sessionSetupSecBuf returns the SPNEGO-wrapped security buffer of an
// incoming SMB2 SESSION_SETUP request, or nil if it can't be located.
// Layout after the 64-byte header: StructureSize(2), Flags(1),
// SecurityMode(1), Capabilities(4), Channel(4), SecurityBufferOffset(2),
// SecurityBufferLength(2), PreviousSessionId(8), then the buffer.
func sessionSetupSecBuf(msg []byte) []byte {
	if len(msg) < 64+24 {
		return nil
	}
	off := int(binary.LittleEndian.Uint16(msg[64+12:]))
	length := int(binary.LittleEndian.Uint16(msg[64+14:]))
	if off <= 0 || length <= 0 || off+length > len(msg) {
		return nil
	}
	return msg[off : off+length]
}
