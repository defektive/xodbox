FROM alpine:latest

ADD dist/xodbox_linux_amd64_v1/xodbox /bin/
WORKDIR /workspace
ENTRYPOINT ["/bin/xodbox"]