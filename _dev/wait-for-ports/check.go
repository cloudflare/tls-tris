// Scan a host for available services, wait until it is ready or fail.
package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	host := os.Args[1]
	var addresses []string
	for _, port := range os.Args[2:] {
		addresses = append(addresses, net.JoinHostPort(host, port))
	}

	start := time.Now()
	deadline := start.Add(5 * time.Second)
	for len(addresses) > 0 {
		c, err := net.DialTimeout("tcp", addresses[0], 100*time.Millisecond)
		if err != nil {
			if time.Now().After(deadline) {
				fmt.Printf("Timeout while waiting for %s: %s\n", addresses[0], err)
				os.Exit(1)
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		c.Close()
		fmt.Printf("Ready: %s (after %.2fs)\n", addresses[0], time.Now().Sub(start).Seconds())
		addresses = addresses[1:]
	}
}
