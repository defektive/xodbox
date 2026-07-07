package smb

import "bytes"

// Minimal ASN.1/DER helpers plus the two SPNEGO tokens the fake server
// needs. We hand-roll the encoding rather than pull in a GSS-API library:
// the tokens are tiny and fixed-shape, and the whole point of the SMB
// handler is to stay dependency-free.

// GSS-API / SPNEGO OIDs (DER value bytes, without the leading tag/len).
var (
	oidSPNEGO  = []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}                         // 1.3.6.1.5.5.2
	oidNTLMSSP = []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a} // 1.3.6.1.4.1.311.2.2.10
)

// derLen encodes an ASN.1 DER length.
func derLen(n int) []byte {
	if n < 0x80 {
		return []byte{lowByte(n)}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{lowByte(n)}, b...)
		n >>= 8
	}
	return append([]byte{lowByte(0x80 | len(b))}, b...)
}

// der wraps content in a TLV with the given tag.
func der(tag byte, content []byte) []byte {
	out := []byte{tag}
	out = append(out, derLen(len(content))...)
	return append(out, content...)
}

// buildNegTokenInit returns the SPNEGO negTokenInit advertising NTLMSSP,
// used as the security buffer of the SMB2 NEGOTIATE response.
func buildNegTokenInit() []byte {
	oid := der(0x06, oidNTLMSSP)         // MechType OID
	mechList := der(0x30, oid)           // SEQUENCE OF MechType
	mechTypes := der(0xa0, mechList)     // [0] mechTypes
	inner := der(0x30, mechTypes)        // NegTokenInit SEQUENCE
	negInit := der(0xa0, inner)          // [0] negTokenInit
	spnegoOID := der(0x06, oidSPNEGO)    // SPNEGO OID
	gss := append(spnegoOID, negInit...) //nolint:gocritic // OID then token
	return der(0x60, gss)                // [APPLICATION 0]
}

// buildNegTokenResp wraps an NTLMSSP CHALLENGE in an SPNEGO negTokenResp
// with negState=accept-incomplete, used as the security buffer of the
// SESSION_SETUP (MORE_PROCESSING_REQUIRED) response.
func buildNegTokenResp(ntlmToken []byte) []byte {
	negState := der(0xa0, der(0x0a, []byte{0x01})) // [0] ENUMERATED accept-incomplete
	supported := der(0xa1, der(0x06, oidNTLMSSP))  // [1] supportedMech
	respToken := der(0xa2, der(0x04, ntlmToken))   // [2] responseToken OCTET STRING
	seq := der(0x30, concat(negState, supported, respToken))
	return der(0xa1, seq) // [1] negTokenResp
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// findNTLMSSP returns the NTLMSSP message embedded anywhere inside a
// (possibly SPNEGO-wrapped) security buffer. Because NTLMSSP messages run
// to the end of their containing buffer, everything from the signature
// onward is the message. Returns nil when no signature is present.
func findNTLMSSP(secBuf []byte) []byte {
	i := bytes.Index(secBuf, ntlmSignature)
	if i < 0 {
		return nil
	}
	return secBuf[i:]
}
