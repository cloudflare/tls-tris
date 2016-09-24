FROM scratch

# GOOS=linux ../go.sh build -v -i .
ADD tris-localserver ./

ENV TLSDEBUG error

EXPOSE 443
EXPOSE 4443
CMD [ "./tris-localserver", "0.0.0.0:443", "0.0.0.0:4443" ]
