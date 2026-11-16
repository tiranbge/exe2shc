package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	path := `C:\Windows\System32\zh-CN\whoami.exe.mui`
	u32 := syscall.NewLazyDLL("user32.dll")
	lsw := u32.NewProc("LoadStringW")
	llew := syscall.NewLazyDLL("kernel32.dll").NewProc("LoadLibraryExW")
	for _, flag := range []uintptr{0x2, 0x20, 0x2 | 0x20} {
		p, _ := syscall.UTF16PtrFromString(path)
		h, _, e := llew.Call(uintptr(unsafe.Pointer(p)), 0, flag)
		if h == 0 {
			fmt.Printf("flag=%#x load fail %v\n", flag, e)
			continue
		}
		buf := make([]uint16, 512)
		n, _, e2 := lsw.Call(h, 5001, uintptr(unsafe.Pointer(&buf[0])), 512)
		fmt.Printf("flag=%#x h=%#x LoadStringW ret=%d err=%v str=%q\n", flag, h, n, e2, syscall.UTF16ToString(buf[:n]))
	}
}
