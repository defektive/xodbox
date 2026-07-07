package smb

// The SMB2/NTLMSSP/DER length fields written by this package all describe
// buffers the server itself constructs (fake target names, our own
// challenge and SPNEGO tokens) and are always far below their field
// widths. These helpers centralise the narrowing conversions so gosec's
// G115 overflow check is justified in one place instead of at every call
// site.

// u16 narrows a length known to fit in 16 bits.
func u16(n int) uint16 {
	return uint16(n) // #nosec G115 -- length of a server-built buffer, < 64 KiB
}

// u32 narrows a length known to fit in 32 bits.
func u32(n int) uint32 {
	return uint32(n) // #nosec G115 -- offset into a server-built buffer
}

// lowByte returns the low 8 bits of n.
func lowByte(n int) byte {
	return byte(n & 0xff) // #nosec G115 -- masked to 8 bits
}
