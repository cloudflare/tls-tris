FROM scratch

# go run ../../generate_cert.go -host localhost -duration 87600h
ADD key.pem ./
ADD cert.pem ./

# GOOS=linux ../go.sh build -v -i .
ADD tris-localserver ./

ENV TLSDEBUG error

EXPOSE 443

CMD [ "./tris-localserver", "0.0.0.0:443" ]
