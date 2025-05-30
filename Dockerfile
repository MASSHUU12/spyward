FROM fedora:42

RUN dnf install -y \
    iputils ip iptables ip6tables nftables libnetfilter_queue-devel \
    unzip wget \
    ncurses \
    dub ldc \
    man \
    && dnf clean all

RUN rm -rf /var/lib/apt/lists/*

WORKDIR /app

CMD ["bash"]
