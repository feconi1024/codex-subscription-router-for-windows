package permissions

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

var (
	advapi            = syscall.NewLazyDLL("advapi32.dll")
	convertDescriptor = advapi.NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
	getDACL           = advapi.NewProc("GetSecurityDescriptorDacl")
	setNamedSecurity  = advapi.NewProc("SetNamedSecurityInfoW")
	localFree         = syscall.NewLazyDLL("kernel32.dll").NewProc("LocalFree")
)

func secure(path string, directory bool) error {
	if err := checkType(path, directory); err != nil {
		return err
	}
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attributes, err := syscall.GetFileAttributes(name)
	if err != nil {
		return err
	}
	if attributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("refusing a reparse point for private state: %s", path)
	}
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	sid, err := user.User.Sid.String()
	if err != nil {
		return err
	}
	inherit := ""
	if directory {
		inherit = "OICI"
	}
	sddl, err := syscall.UTF16PtrFromString("D:P(A;" + inherit + ";FA;;;" + sid + ")(A;" + inherit + ";FA;;;SY)")
	if err != nil {
		return err
	}
	var descriptor, dacl uintptr
	var present, defaulted uint32
	ok, _, callErr := convertDescriptor.Call(uintptr(unsafe.Pointer(sddl)), 1, uintptr(unsafe.Pointer(&descriptor)), 0)
	if ok == 0 {
		return fmt.Errorf("create private DACL: %w", callErr)
	}
	defer localFree.Call(descriptor)
	ok, _, callErr = getDACL.Call(descriptor, uintptr(unsafe.Pointer(&present)), uintptr(unsafe.Pointer(&dacl)), uintptr(unsafe.Pointer(&defaulted)))
	if ok == 0 || present == 0 || dacl == 0 {
		return fmt.Errorf("extract private DACL: %v", callErr)
	}
	// SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION.
	status, _, _ := setNamedSecurity.Call(uintptr(unsafe.Pointer(name)), 1, 0x80000004, 0, 0, dacl, 0)
	runtime.KeepAlive(name)
	if status != 0 {
		return fmt.Errorf("protect state DACL: %w", syscall.Errno(status))
	}
	return nil
}
