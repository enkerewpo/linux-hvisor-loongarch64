#!/bin/bash

# https://www.qemu.org/docs/master/system/loongarch/virt.html

CHOSEN_ROOT=$(cat chosen_root)
KERNEL_PATH=linux-${CHOSEN_ROOT}/vmlinux

qemu-system-loongarch64 -machine virt -m 16G -cpu la464 \
    -smp 1 -kernel $KERNEL_PATH \
    -serial mon:stdio --nographic