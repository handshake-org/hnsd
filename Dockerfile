FROM alpine AS builder

RUN apk update && \
    apk --no-cache --update add build-base

RUN apk add git automake autoconf libtool unbound-dev

COPY . /

RUN ./autogen.sh && ./configure && make

FROM alpine:latest

RUN apk update && apk upgrade 

#.required dependency
RUN apk add unbound-libs

COPY --from=builder /hnsd /usr/local/bin/hnsd

ENTRYPOINT ["/usr/local/bin/hnsd"]

CMD []