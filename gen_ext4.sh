#!/bin/bash
qemu-img create -f raw nvme_ext4.img 256M
sudo mkfs.ext4 nvme_ext4.img