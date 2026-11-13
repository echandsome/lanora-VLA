package netcfg

import _ "embed"

//go:embed wintun/amd64/wintun.dll
var wintunDLL []byte

// Machine code for "return this value at once", used by blockDeviceRemoval.
var (
	stubReturnInvalidHandle = []byte{0x48, 0x83, 0xC8, 0xFF, 0xC3} // or rax, -1; ret
	stubReturnFalse         = []byte{0x31, 0xC0, 0xC3}             // xor eax, eax; ret
)
