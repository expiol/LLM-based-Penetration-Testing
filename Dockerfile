# Must be amd64: i386/multilib apt repos, radare2 .deb, and runtime match run.py (--platform linux/amd64).
FROM --platform=linux/amd64 ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN printf '%s\n' \
    'Acquire::Retries "5";' \
    'Acquire::http::Timeout "30";' \
    > /etc/apt/apt.conf.d/80-retries

RUN dpkg --add-architecture i386
RUN apt-get update && apt-get install -y \
    sudo curl netcat \
    build-essential pkg-config gdb gdbserver \
    python3-dev python3-pip python3-venv \
    libssl-dev libffi-dev \
    libtbb2 libtbb-dev libjpeg-dev libpng-dev libtiff-dev \
    bsdmainutils fdisk file \
    sagemath sqlmap nikto apktool nmap \
    libc6-i386 libc6-dev:i386 gcc-multilib \
    g++-multilib \
    wget jq vim \
    p11-kit p11-kit-modules \
    rustc cargo sleuthkit \
    openjdk-17-jdk openjdk-17-jre \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp
RUN curl -LO https://github.com/radareorg/radare2/releases/download/5.8.8/radare2_5.8.8_amd64.deb && \
    curl -LO https://github.com/radareorg/radare2/releases/download/5.8.8/radare2-dev_5.8.8_amd64.deb && \
    apt-get install -y ./radare2_5.8.8_amd64.deb ./radare2-dev_5.8.8_amd64.deb && \
    rm -f ./radare2-dev_5.8.8_amd64.deb ./radare2_5.8.8_amd64.deb

RUN curl -LO https://github.com/skylot/jadx/releases/download/v1.4.7/jadx-1.4.7.zip && \
    unzip -d /usr/local jadx-1.4.7.zip && \
    rm -f jadx-1.4.7.zip

RUN python3 -m pip install --upgrade pip && python3 -m pip install pwntools gmpy2 angr chepy pycryptodome z3-solver sympy ROPgadget uncompyle6 decompyle3

RUN apt-get update && apt-get install -y \
    ltrace strace upx-ucl binwalk exiftool steghide foremost \
    tshark fcrackzip john openssl \
    libzxing-core-java libzxing-javase-java zbar-tools python3-pyzbar \
    && rm -rf /var/lib/apt/lists/*

RUN printf '%s\n' \
    '#!/bin/sh' \
    'exec java -cp /usr/share/java/core.jar:/usr/share/java/javase.jar com.google.zxing.client.j2se.CommandLineRunner "$@"' \
    > /usr/local/bin/zxing && chmod +x /usr/local/bin/zxing

# Radare2 Ghidra decompiler plugin
RUN r2pm -ci r2ghidra || true

RUN ln -s -f /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-trust.so /usr/lib/x86_64-linux-gnu/nss/libnssckbi.so
RUN ln -s -f /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-trust.so /usr/lib/firefox/libnssckbi.so || true

ARG HOST_UID=1000
ARG USERNAME=ctfplayer
ARG USER_UID=$HOST_UID
ARG USER_GID=$USER_UID
RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME \
    && echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME

USER $USERNAME
WORKDIR /home/$USERNAME
RUN mkdir ctf_files

COPY docker_entrypoint.py /home/$USERNAME/.entrypoint.py
CMD ["python3", "/home/ctfplayer/.entrypoint.py"]
