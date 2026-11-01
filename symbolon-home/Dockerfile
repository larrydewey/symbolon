# Symbolon Home: the household box (relay, witnesses, a cosigner per
# person, pairing). The agent is one static binary; nothing else is in the
# image. Build with ./build.sh.
FROM scratch
ARG TARGETARCH
COPY bin/symbolon-${TARGETARCH} /symbolon
# The cosigner holds a whole protocol session in memory (no collector):
# key generation peaks near 1.2 GB, a re-share (adding a device) near 10 GB.
ENV RESID_MEM_LIMIT=12000
USER 65532:65532
VOLUME /data
EXPOSE 47100-47104
ENTRYPOINT ["/symbolon"]
CMD ["home", "serve", "/data"]
