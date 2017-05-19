package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

var tlsVersionToName = map[string]uint16{
	"tls10": tls.VersionTLS10,
	"tls11": tls.VersionTLS11,
	"tls12": tls.VersionTLS12,
	"tls13": tls.VersionTLS13,
}

//Usage client args host:port
func main() {
	var version string
	var addr string
	var enableEMS bool
	var config tls.Config
	flag.StringVar(&version, "version", "tls12", "Version of TLS to use")
	flag.BoolVar(&enableEMS, "m", false, "Enable EMS")
	flag.Parse()
	config.MinVersion = tlsVersionToName[version]
	config.MaxVersion = tlsVersionToName[version]
	config.InsecureSkipVerify = true
	config.DisableExtendedMasterSecret = !enableEMS
	addr = flag.Arg(0)
	conn, err := tls.Dial("tcp", addr, &config)
	if err != nil {
		fmt.Println("Error %s", err)
		os.Exit(1)
	}
	var req http.Request
	var response *http.Response
	req.Method = "GET"
	req.URL,err = url.Parse("https://"+addr + "/")
	if err !=nil {
		fmt.Println("Failed to parse url");
		os.Exit(1)
	}
	req.Write(conn)
	reader := bufio.NewReader(conn)
	response, err = http.ReadResponse(reader, nil)
	if err != nil{
		fmt.Println("HTTP problem");
		fmt.Println(err);
		os.Exit(1)
	}
	io.Copy(os.Stdout, response.Body)
	conn.Close()
	os.Exit(0)
}
