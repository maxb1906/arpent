package i18n

import (
	"syscall"
	"unsafe"
)

// systemLocale lit la locale de l'utilisateur via GetUserDefaultLocaleName
// (kernel32), par exemple "fr-BE".
func systemLocale() string {
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("GetUserDefaultLocaleName")
	if proc.Find() != nil {
		return ""
	}
	const localeNameMaxLength = 85
	buf := make([]uint16, localeNameMaxLength)
	n, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf)
}
