package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func main() {
	k := syscall.NewLazyDLL("kernel32.dll")
	gmfn := k.NewProc("GetModuleFileNameW")
	gmfa := k.NewProc("GetModuleFileNameA")

	buf := make([]uint16, 512)
	r, _, _ := gmfn.Call(0, uintptr(unsafe.Pointer(&buf[0])), 512)
	abuf := make([]byte, 512)
	ra, _, _ := gmfa.Call(0, uintptr(unsafe.Pointer(&abuf[0])), 512)

	fmt.Printf("W len=%d path=%q\n", r, syscall.UTF16ToString(buf))
	fmt.Printf("A len=%d path=%q\n", ra, string(abuf[:ra]))
}
