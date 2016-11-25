FROM scratch

ENV TLSDEBUG error

EXPOSE 1443
EXPOSE 2443
EXPOSE 3443
EXPOSE 4443
EXPOSE 5443

# GOOS=linux ../go.sh build -v -i .
ADD tris-localserver ./

CMD [ "./tris-localserver", "0.0.0.0:1443", "0.0.0.0:2443", "0.0.0.0:3443", "0.0.0.0:4443", "0.0.0.0:5443" ]
