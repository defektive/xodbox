FROM alpine:3.21

# Run as a non-root user. xodbox listens on user-space ports by default;
# bind low ports (e.g. 53, 80, 443) via the docker run/-p mapping.
RUN addgroup -S xodbox && adduser -S -G xodbox xodbox

ADD --chown=xodbox:xodbox dist/xodbox_linux_amd64_v1/xodbox /bin/

USER xodbox
WORKDIR /workspace
ENTRYPOINT ["/bin/xodbox"]