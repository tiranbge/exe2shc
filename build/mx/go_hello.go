package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Printf("GO-HELLO args=%d\n", len(os.Args)-1)
	for i, a := range os.Args[1:] {
		fmt.Printf("  arg[%d]=%s\n", i+1, a)
	}
	os.Exit(5)
}
