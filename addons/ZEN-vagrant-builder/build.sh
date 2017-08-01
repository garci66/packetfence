#!/bin/bash

rm -f \
        work/box.ovf \
        work/box-disk1.vmdk \
        work/box.ova \
        work/package.box \
        work/vagrant_private_key \
        work/Vagrantfile

rm -f PacketFence-ZEN.ova

vagrant destroy -f

vagrant up

vagrant halt

VBoxManage modifyvm PacketFence-ZEN --memory 8096

VBoxManage modifyvm PacketFence-ZEN --uartmode1 disconnected

vagrant package

mkdir -p work
mv package.box work/
cd work/
tar -xvf package.box

../fix_ovf_alt box.ovf
\mv vmx_box.ovf box.ovf

#yes | cp ../box-release.ovf box.ovf

ovftool --lax box.ovf box.ova

mv box.ova ../PacketFence-ZEN.ova

