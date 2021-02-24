FROM golang:1.15.8-alpine3.13 AS build

WORKDIR /opt/build
COPY . /opt/build
RUN apk add --no-cache bcc-dev=0.18.0-r0 build-base linux-headers
RUN go build .

FROM alpine:3.13

RUN apk add --no-cache bcc=0.18.0-r0
RUN apk add libc6-compat
COPY --from=build /opt/build/ebpf-userspace-exporter /

ENTRYPOINT ["/ebpf-userspace-exporter"]
