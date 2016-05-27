//+build ignore

package main

import (
	"log"
	"os"

	"github.com/bifurcation/mint"
)

func main() {
	conn, err := mint.Dial("tcp", os.Args[1], nil)
	if err != nil {
		log.Fatal(err)
	}
	if _, err := conn.Write([]byte("Hello, World!")); err != nil {
		log.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		log.Fatal(err)
	}
}
