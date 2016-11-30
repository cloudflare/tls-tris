FROM golang:1.7-alpine

RUN apk add --update \
    git \
  && rm -rf /var/cache/apk/*

RUN go get github.com/bifurcation/mint

# Draft 18
ARG REVISION=52f9f98

RUN cd /go/src/github.com/bifurcation/mint && git fetch https://github.com/FiloSottile/mint
RUN cd /go/src/github.com/bifurcation/mint && git checkout $REVISION

ADD mint-client.go /mint-client.go
RUN GOBIN=/ go install /mint-client.go

ENV MINT_LOG=*

ADD run.sh /run.sh
ENTRYPOINT ["/run.sh"]
