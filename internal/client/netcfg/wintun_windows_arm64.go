package netcfg

import _ "embed"

//go:embed wintun/arm64/wintun.dll
var wintunDLL []byte

// Machine code for "return this value at once", used by blockDeviceRemoval.
var (
	stubReturnInvalidHandle = []byte{0x00, 0x00, 0x80, 0x92, 0xC0, 0x03, 0x5F, 0xD6} // mov x0, #-1; ret
	stubReturnFalse         = []byte{0xE0, 0x03, 0x1F, 0x2A, 0xC0, 0x03, 0x5F, 0xD6} // mov w0, wzr; ret
)
