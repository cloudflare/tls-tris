package main

import (
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
)

var htmlBody = []byte(`
<!DOCTYPE html>
<p>Hello!
<code><pre>
`)

func main() {
	http.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request) {
		rw.Write(htmlBody)
		for name, value := range r.Header {
			fmt.Fprintf(rw, "%s: %s\n", name, html.EscapeString(value[0]))
		}
	})
	log.Println(http.ListenAndServe(os.Args[1], nil))
}
