package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func msg(c uint32) string {
	b := make([]uint16, 512)
	n, _ := syscall.FormatMessage(0x1000, c, 0, 0, b, nil)
	if n > 0 {
		return syscall.UTF16ToString(b[:n])
	}
	return "?"
}

func main() {
	for _, c := range []uint32{1812, 1815, 15105} {
		fmt.Printf("%d: %s\n", c, msg(c))
	}
	u32 := syscall.NewLazyDLL("user32.dll")
	lsw := u32.NewProc("LoadStringW")
	llew := syscall.NewLazyDLL("kernel32.dll").NewProc("LoadLibraryExW")
	for _, path := range []string{
		`C:\Windows\System32\zh-CN\whoami.exe.mui`,
		`\?\C:\Windows\System32\zh-CN\whoami.exe.mui`,
		`\??\C:\Windows\System32\zh-CN\whoami.exe.mui`,
	} {
		p, _ := syscall.UTF16PtrFromString(path)
		h, _, e := llew.Call(uintptr(unsafe.Pointer(p)), 0, 0x20)
		if h == 0 {
			fmt.Printf("%s -> fail %v\n", path, e)
			continue
		}
		buf := make([]uint16, 256)
		n, _, e2 := lsw.Call(h, 5001, uintptr(unsafe.Pointer(&buf[0])), 256)
		fmt.Printf("%s -> h=%#x ret=%d err=%v str=%q\n", path, h, n, e2, syscall.UTF16ToString(buf[:n]))
	}
}
