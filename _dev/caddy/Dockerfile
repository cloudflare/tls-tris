FROM scratch

# docker create -v /root/.caddy --name caddy-data caddy /bin/true
# docker run --restart=always -d --volumes-from caddy-data --link echo -p 80:80 -p 443:443 caddy

# GOOS=linux ../go.sh build -v -i github.com/mholt/caddy/caddy
ADD caddy caddy
ADD Caddyfile Caddyfile
ADD https://mkcert.org/generate/ /etc/ssl/certs/ca-certificates.crt

EXPOSE 80
EXPOSE 443

ENV TLSDEBUG short
ENV HOME /root/

CMD [ "/caddy" ]
