FROM fedora:42

RUN dnf update -y
RUN dnf install -y \
    iputils ip iptables ip6tables nftables libnetfilter_queue-devel \
    unzip wget curl \
    ncurses \
    clang pkg-config \
    man \
    && dnf clean all

RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /app

CMD ["bash"]
