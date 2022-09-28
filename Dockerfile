FROM alpine AS build
COPY . /

RUN apk add --no-cache \
  build-base \
  bash \
  automake \
  autoconf \
  libtool \
  unbound-dev
RUN ./autogen.sh && ./configure && make

FROM alpine
RUN apk add --no-cache unbound-libs
COPY --from=build /hnsd /usr/local/bin/hnsd

ENTRYPOINT ["/usr/local/bin/hnsd"]
CMD []
