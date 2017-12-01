FROM haskell:8.0

RUN git clone https://github.com/kazu-yamamoto/hs-tls.git \
    -b tls13 --single-branch

# branch tls13 (as of 12 December 2017)
ARG REVISION=a7936cfcf4ea95bb35b34b1640a356cee69157d6

RUN cd hs-tls && git fetch && git checkout $REVISION
RUN cd hs-tls && stack build

ADD run.sh /run.sh
ADD httpreq.txt /httpreq.txt
WORKDIR /hs-tls
ENTRYPOINT ["/run.sh"]
