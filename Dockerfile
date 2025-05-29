FROM fedora:42

RUN dnf install -y \
    iputils ip \
    unzip wget \
    dub ldc \
    && dnf clean all

RUN rm -rf /var/lib/apt/lists/*

WORKDIR /app

CMD ["bash"]
