FROM buildpack-deps

ENV TLSDEBUG error

EXPOSE 1443
EXPOSE 2443
EXPOSE 3443
EXPOSE 4443
EXPOSE 5443
EXPOSE 6443

# GOOS=linux ../go.sh build -v -i .
ADD tris-localserver /
ADD runner.sh /

CMD [ "./runner.sh" ]
