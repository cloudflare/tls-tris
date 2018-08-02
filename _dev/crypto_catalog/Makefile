all:
	make -f ~/repos/tls-tris/_dev/Makefile swap_tls
	GOROOT=../GOROOT/linux_amd64 go build client.go
	GOROOT=../GOROOT/linux_amd64 go build server.go
