package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	k := syscall.NewLazyDLL("kernel32.dll")
	llew := k.NewProc("LoadLibraryExW")
	lsw := k.NewProc("LoadStringW")

	paths := []string{
		`C:\Windows\System32\zh-CN\whoami.exe.mui`,
		`C:\Windows\SysWOW64\zh-CN\whoami.exe.mui`,
		`C:\Windows\System32\en-US\whoami.exe.mui`,
	}
	for _, p := range paths {
		u, _ := syscall.UTF16PtrFromString(p)
		h, _, err := llew.Call(uintptr(unsafe.Pointer(u)), 0, 2)
		fmt.Printf("%-52s h=%x err=%v\n", p, h, err)
		if h != 0 {
			buf := make([]uint16, 512)
			r, _, e2 := lsw.Call(h, 5001, uintptr(unsafe.Pointer(&buf[0])), 512)
			fmt.Printf("   LoadStringW(5001) -> n=%d %q err=%v\n", r, syscall.UTF16ToString(buf), e2)
		}
	}
}
