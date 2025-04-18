#!/bin/bash

# https://www.qemu.org/docs/master/system/loongarch/virt.html

CHOSEN=$(cat chosen)
KERNEL_PATH=linux-${CHOSEN}/vmlinux

qemu-system-loongarch64 -machine virt -m 16G -cpu la464 \
    -smp 1 -kernel $KERNEL_PATH \
    -device igb,netdev=net0,bus=pcie.0,addr=0x6 \
    -netdev user,id=net0 \
    -device nvme,drive=nvme0,bus=pcie.0,addr=0x5,serial=1234567890 \
    -drive file=nvme_ext4.img,if=none,id=nvme0,format=raw \
    -serial mon:stdio --nographic