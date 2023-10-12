FROM ubuntu:20.04

# Basic net and development tools
RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get update && \
    apt-get install -y ssl-cert wget curl \
    telnet openssh-client net-tools iputils-ping sudo && \
    apt-get install -y build-essential gcc clang python perl zip git-core && \
    apt-get install -y vim git ninja-build tree

# QEMU base dependencies
RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get install -y pkg-config \
    zlib1g-dev libglib2.0-dev libpixman-1-dev libfdt-dev

# Python
RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get install -y python3-setuptools python3-pip uuid-runtime

# User Setup
RUN useradd -m -s /bin/bash ubuntu \
    && echo 'ubuntu ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/ubuntu
USER ubuntu
WORKDIR /home/ubuntu

# Build QEMU
COPY xunpack.patch /home/ubuntu
RUN git clone https://github.com/qemu/qemu.git qemu \
    && cd qemu \
    && git checkout 972e848b53970d12cb2ca64687ef8ff797fb6236 \
    && cd .. \
    && patch -p0 < xunpack.patch \
    && mkdir qemu/build 

WORKDIR /home/ubuntu/qemu/build
RUN ../configure --enable-plugins --enable-xunpack --target-list=x86_64-softmmu,x86_64-linux-user \
    && make \
    && sudo make install

# Build QEMU Plugins
WORKDIR /home/ubuntu/qemu/build/contrib/plugins
RUN make

# ELFPack
#  riscv-disassembler
WORKDIR /home/ubuntu/
COPY riscv-assembler /home/ubuntu/riscv-assembler
WORKDIR /home/ubuntu/riscv-assembler
RUN pip3 install -r requirements.txt \
    && sudo python3 setup.py install

#  elfpack
WORKDIR /home/ubuntu/
COPY elfpack /home/ubuntu/elfpack
RUN pip3 install elfpack/ \
    && pip3 install keystone-engine

# Zelos
WORKDIR /home/ubuntu/
COPY zelos /home/ubuntu/zelos
RUN pip3 install zelos/

# Scripts, e.g., SelectiveDump etc
WORKDIR /home/ubuntu/
COPY scripts /home/ubuntu/scripts
COPY buildroot /home/ubuntu/buildroot
RUN sudo chown -R ubuntu.ubuntu scripts \
    && sudo chown -R ubuntu.ubuntu buildroot \
    && sudo mkdir /mnt/rootfs
RUN pip3 install -r scripts/requirements.txt
RUN git clone https://github.com/marin-m/vmlinux-to-elf.git

WORKDIR /home/ubuntu/
CMD ["/bin/bash"]
