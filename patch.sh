# the yt6801 patch, however we cannot successfully apply it by now (2025.4.1) - wheatfox
b4 am -o patch 1482683f626c0743e3ec53161dd291de3a6726f6.camel@mailbox.org
# cd linux-6.13.7
cd linux-git # caution, we are using the latest git code of linux kernel
git am ../patch/v3_20250228_frank_sae_net_yt6801_add_motorcomm_yt6801_pcie_driver.mbx
# git am --abort # if you want to abort the patch