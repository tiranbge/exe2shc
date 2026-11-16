package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: loader32.exe <shellcode.bin> [args...]")
		return
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Println("read:", err)
		return
	}
	k := syscall.NewLazyDLL("kernel32.dll")
	va := k.NewProc("VirtualAlloc")
	ct := k.NewProc("CreateThread")
	wf := k.NewProc("WaitForSingleObject")
	ge := k.NewProc("GetExitCodeThread")
	addr, _, e := va.Call(0, uintptr(len(data)), 0x3000, 0x40)
	if addr == 0 {
		fmt.Println("alloc:", e)
		return
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(data)), data)
	h, _, e := ct.Call(0, 0, addr, 0, 0, 0)
	if h == 0 {
		fmt.Println("thread:", e)
		return
	}
	wf.Call(h, 20000)
	var code uint32
	ge.Call(h, uintptr(unsafe.Pointer(&code)))
	fmt.Printf("[loader32] exit=%d\n", code)
}
