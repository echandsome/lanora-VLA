package settings

import (
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// On Windows secrets are encrypted with the Data Protection API under the
// account the client runs as. The state file lives in a directory other
// users can read, but they cannot decrypt the identity or the password.

func blob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

func protect(b []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptProtectData(blob(b), nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

func unprotect(b []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(blob(b), nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

func defaultDir() (string, error) {
	// %ProgramData%: shared by the service and every user's window.
	dir := os.Getenv("ProgramData")
	if dir == "" {
		dir = `C:\ProgramData`
	}
	return filepath.Join(dir, "Lanora"), nil
}

func userDir() (string, error) {
	dir, err := os.UserCacheDir() // %LocalAppData%
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "Lanora"), nil
}
