FROM scratch

# ( cd _dev/tris-localserver && GOOS=linux ../go.sh build -v -i . &&
# docker build -t tris-localserver . && docker run -i --env TLSDEBUG=keys -p 4444:443 --rm tris-localserver )

# go run ../../generate_cert.go -host localhost -duration 87600h
ADD key.pem ./
ADD cert.pem ./

# GOOS=linux ../go.sh build -v -i .
ADD tris-localserver ./

ENV TLSDEBUG error

EXPOSE 443

CMD [ "./tris-localserver", "0.0.0.0:443" ]
