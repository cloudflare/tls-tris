FROM scratch

ENV TLSDEBUG error

EXPOSE 443
EXPOSE 4443

# GOOS=linux ../go.sh build -v -i .
ADD tris-localserver ./

CMD [ "./tris-localserver", "0.0.0.0:443", "0.0.0.0:4443" ]
