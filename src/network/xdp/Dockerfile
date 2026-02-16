FROM fedora:41
COPY xdp /usr/bin/
RUN dnf install -y iproute cri-tools jq && dnf clean all
ENTRYPOINT ["/usr/bin/xdp"]
