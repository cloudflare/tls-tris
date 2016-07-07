FROM golang:1.7-alpine

# docker create -v /root/.caddy --name caddy-data caddy /bin/true
# docker run -d --restart always --volumes-from caddy-data -p 80:80 -p 443:443 caddy

RUN apk add --update \
    ca-certificates \
    git \
	bash \
	build-base \
  && rm -rf /var/cache/apk/*

RUN go get -d -v github.com/mholt/caddy/caddy
RUN git clone https://github.com/cloudflare/tls-tris
RUN ./tls-tris/_dev/go.sh install -v github.com/mholt/caddy/caddy

ADD Caddyfile Caddyfile

EXPOSE 80
EXPOSE 443

ENV TLSDEBUG error

CMD [ "/go/bin/caddy" ]
