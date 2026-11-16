package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

func cstr(p *byte) string {
	var b []byte
	for i := 0; ; i++ {
		c := *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + uintptr(i)))
		if c == 0 {
			break
		}
		b = append(b, c)
	}
	return string(b)
}

func wstr(p *uint16) string {
	var r []rune
	for i := 0; ; i++ {
		c := *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(p)) + uintptr(i)*2))
		if c == 0 {
			break
		}
		r = append(r, rune(c))
	}
	return string(r)
}

func main() {
	k := syscall.NewLazyDLL("kernel32.dll")
	ga := k.NewProc("GetCommandLineA")
	gw := k.NewProc("GetCommandLineW")
	a, _, _ := ga.Call()
	w, _, _ := gw.Call()
	as := ""
	if a != 0 {
		as = cstr((*byte)(unsafe.Pointer(a)))
	}
	ws := ""
	if w != 0 {
		ws = wstr((*uint16)(unsafe.Pointer(w)))
	}
	fmt.Printf("A=[%s]\nW=[%s]\nOSARGS=%d %v\n", as, ws, len(os.Args), os.Args)
}
