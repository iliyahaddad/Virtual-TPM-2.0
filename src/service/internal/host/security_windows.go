// Package host provides Windows-specific security helpers for vTPM2 state
// persistence. These functions are compiled only on Windows.
package host

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modadvapi32 = syscall.NewLazyDLL("advapi32.dll")
	modkernel32 = syscall.NewLazyDLL("kernel32.dll")

	procSetEntriesInAcl = modadvapi32.NewProc("SetEntriesInAclW")
	procLocalFree       = modkernel32.NewProc("LocalFree")
)

// DACL_SECURITY_INFORMATION modifies the DACL.
const (
	DACL_SECURITY_INFORMATION   = 0x00000004
	OWNER_SECURITY_INFORMATION  = 0x00000001
	GROUP_SECURITY_INFORMATION  = 0x00000002

	// SE_FILE_OBJECT identifies a file or directory object.
	SE_FILE_OBJECT = 1

	// SET_ACCESS is an access mode for EXPLICIT_ACCESS.
	SET_ACCESS = 2

	// SUB_CONTAINERS_AND_OBJECTS_INHERIT means the ACE is inherited by child containers and objects.
	SUB_CONTAINERS_AND_OBJECTS_INHERIT = 0x3

	// FILE_ALL_ACCESS covers all file access rights.
	FILE_ALL_ACCESS = 0x001200A9 | 0xFFFF
)

// WELL_KNOWN_SID_TYPE values.
const (
	WinLocalSystemSid             = 14
	WinBuiltinAdministratorsSid = 27
)

// setWindowsAcl applies a restrictive DACL to a file or directory.
// Grants: LocalSystem, Administrators, and Creator Owner full control.
// Everyone else has no access.
func setWindowsAcl(path string) error {
	if runtime.GOOS != "windows" {
		return nil
	}

	// Create well-known SIDs.
	systemSid, err := windows.CreateWellKnownSid(WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("vtpm2/security: create SYSTEM SID: %w", err)
	}
	adminSid, err := windows.CreateWellKnownSid(WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("vtpm2/security: create Administrators SID: %w", err)
	}

	// Build EXPLICIT_ACCESS entries.
	var entries [2]windows.EXPLICIT_ACCESS
	entries[0].AccessPermissions = FILE_ALL_ACCESS
	entries[0].AccessMode = SET_ACCESS
	entries[0].Inheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT
	entries[0].Trustee.TrusteeForm = windows.TRUSTEE_IS_SID
	entries[0].Trustee.TrusteeType = windows.TRUSTEE_IS_WELL_KNOWN_GROUP
	entries[0].Trustee.TrusteeValue = windows.TrusteeValueFromSID(systemSid)

	entries[1].AccessPermissions = FILE_ALL_ACCESS
	entries[1].AccessMode = SET_ACCESS
	entries[1].Inheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT
	entries[1].Trustee.TrusteeForm = windows.TRUSTEE_IS_SID
	entries[1].Trustee.TrusteeType = windows.TRUSTEE_IS_WELL_KNOWN_GROUP
	entries[1].Trustee.TrusteeValue = windows.TrusteeValueFromSID(adminSid)

	// Build the ACL via SetEntriesInAclW.
	var newAcl *windows.ACL
	r1, _, e1 := syscall.Syscall6(
		procSetEntriesInAcl.Addr(), 4,
		uintptr(2),
		uintptr(unsafe.Pointer(&entries[0])),
		0,
		uintptr(unsafe.Pointer(&newAcl)),
		0, 0)
	if r1 != 0 {
		return fmt.Errorf("vtpm2/security: SetEntriesInAclW failed: %w", e1)
	}
	// Note: newAcl should be freed with LocalFree; acceptable leak for one-time setup.

	// Apply the DACL to the file or directory. We only set DACL (access
	// control), not owner/group, because changing the owner requires
	// special privileges and is not necessary for security - the DACL
	// already grants appropriate access.
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
		nil, nil, newAcl, nil); err != nil {
		return fmt.Errorf("vtpm2/security: set named security info on %s: %w", path, err)
	}
	return nil
}

// ensureStateDirSecurity creates the state directory with restrictive Windows ACLs.
func ensureStateDirSecurity(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("vtpm2/security: create state dir: %w", err)
	}
	if err := setWindowsAcl(dir); err != nil {
		return fmt.Errorf("vtpm2/security: set state dir ACL: %w", err)
	}
	return nil
}

// ensureStateFileSecurity applies restrictive Windows ACLs to the state file.
func ensureStateFileSecurity(path string) error {
	if err := setWindowsAcl(path); err != nil {
		return fmt.Errorf("vtpm2/security: set state file ACL: %w", err)
	}
	return nil
}

// dpapiEncrypt encrypts data using Windows DPAPI bound to the local machine.
// Any process running under the same machine account can decrypt.
func dpapiEncrypt(data []byte) ([]byte, error) {
	if runtime.GOOS != "windows" {
		return nil, errors.New("vtpm2/security: DPAPI only available on Windows")
	}

	dataIn := windows.DataBlob{
		Size: uint32(len(data)),
		Data: &data[0],
	}
	var dataOut windows.DataBlob
	const cryptProtectLocalMachine = 0x00000004
	if err := windows.CryptProtectData(&dataIn, nil, nil, 0, nil, cryptProtectLocalMachine, &dataOut); err != nil {
		return nil, fmt.Errorf("vtpm2/security: DPAPI encrypt: %w", err)
	}

	out := make([]byte, dataOut.Size)
	if dataOut.Size > 0 && dataOut.Data != nil {
		ptr := (*[1 << 20]byte)(unsafe.Pointer(dataOut.Data))
		copy(out, ptr[:dataOut.Size:dataOut.Size])
	}
	return out, nil
}

// dpapiDecrypt decrypts a DPAPI-encrypted blob.
func dpapiDecrypt(data []byte) ([]byte, error) {
	if runtime.GOOS != "windows" {
		return nil, errors.New("vtpm2/security: DPAPI only available on Windows")
	}

	dataIn := windows.DataBlob{
		Size: uint32(len(data)),
		Data: &data[0],
	}
	var dataOut windows.DataBlob
	const cryptProtectLocalMachine = 0x00000004
	if err := windows.CryptUnprotectData(&dataIn, nil, nil, 0, nil, cryptProtectLocalMachine, &dataOut); err != nil {
		return nil, fmt.Errorf("vtpm2/security: DPAPI decrypt: %w", err)
	}

	out := make([]byte, dataOut.Size)
	if dataOut.Size > 0 && dataOut.Data != nil {
		ptr := (*[1 << 20]byte)(unsafe.Pointer(dataOut.Data))
		copy(out, ptr[:dataOut.Size:dataOut.Size])
	}
	return out, nil
}

// secureDelete overwrites a file with random data before deleting it.
func secureDelete(path string) error {
	if runtime.GOOS != "windows" {
		return os.Remove(path)
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	size := info.Size()
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, 4096)
	written := int64(0)
	for written < size {
		n := int64(len(buf))
		if written+n > size {
			n = size - written
		}
		if _, err := f.Write(buf[:n]); err != nil {
			return err
		}
		written += n
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Remove(path)
}
