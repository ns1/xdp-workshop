#!/usr/bin/env bash

set -e

XDP_USER="${1:-xdp}"

# Vars to use for installing various packages.
WORKSHOP_TOOLS="git unzip mtr tcpdump bash-completion"
WORKSHOP_DEVEL_PACKAGES="clang gcc llvm make pkg-config bison flex"
BPFTOOL_DEPENDENCIES="libelf-dev python3-docutils"

# disable sudo password checking for the primary ${XDP_USER} user.
# NOTE: This is HIGHLY dangerous DO NOT DO THIS, this is only to facilitate the workshop.
echo "${XDP_USER} ALL=(ALL) NOPASSWD: ALL" | tee -a /etc/sudoers

# Update apt and upgrade installed packages
DEBIAN_FRONTEND="noninteractive" apt-get update -y
DEBIAN_FRONTEND="noninteractive" apt-get upgrade -y

# Install dependancies
DEBIAN_FRONTEND="noninteractive" apt-get install -y \
    ${WORKSHOP_TOOLS} \
    ${WORKSHOP_DEVEL_PACKAGES} \
    ${BPFTOOL_DEPENDENCIES}

# Create some directories
mkdir -p /home/${XDP_USER}/workspace
mkdir -p /home/${XDP_USER}/.ssh

chown ${XDP_USER}:${XDP_USER} /home/${XDP_USER}/.ssh

# Clone the linux kernel git repo
cd /home/${XDP_USER}/workspace/
curl -o linux-5.0.zip -L https://github.com/torvalds/linux/archive/v5.0.zip
unzip linux-5.0.zip
mv linux-5.0/ linux/

# Build bpftool binary and documentation
cd /home/${XDP_USER}/workspace/linux/tools/bpf/bpftool
make
make install
make doc doc-install
cp bash-completion/bpftool /etc/bash_completion.d/bpftool

# Download/Build/Install latest iproute2
cd /home/${XDP_USER}/workspace
curl -o iproute2.tar.gz -L https://mirrors.edge.kernel.org/pub/linux/utils/net/iproute2/iproute2-5.0.0.tar.gz
tar -xzf iproute2.tar.gz
mv iproute2-5.0.0/ iproute2/
cd iproute2
./configure
make
make install

chown -R ${XDP_USER}:${XDP_USER} /home/${XDP_USER}/workspace

mount -o loop /home/${XDP_USER}/VBoxGuestAdditions.iso /mnt
yes | sh /mnt/VBoxLinuxAdditions.run || true
umount /mnt

usermod -aG vboxsf ${XDP_USER}