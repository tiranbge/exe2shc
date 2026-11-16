package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

func main() {
	k := syscall.NewLazyDLL("kernel32.dll")
	gw := k.NewProc("GetCommandLineW")
	p, _, _ := gw.Call()
	w := syscall.UTF16ToString((*[8192]uint16)(unsafe.Pointer(p))[:])
	fmt.Printf("W=[%s]\n", w)
	fmt.Printf("OSARGS=%d\n", len(os.Args))
	for i, a := range os.Args {
		fmt.Printf("  os.Args[%d]=%s\n", i, a)
	}
}
