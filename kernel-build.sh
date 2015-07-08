#!/bin/bash
# for build kernel and make kernel-headers kernel-modules kernel-devel
set -e
set -x

INSTALL_ROOT=$PWD/../forwanglei-test
Arch=mips
asmarch=mips


#make menuconfig ARCH=mips CROSS_COMPILE=mips64el-linux-
make menuconfig

rm -rf $INSTALL_ROOT
mkdir -p $INSTALL_ROOT
mkdir $INSTALL_ROOT/boot

# Make kernel: vmlinux
#make ARCH=mips CROSS_COMPILE=mips64el-linux- -j8
make -j8
cp vmlinux $INSTALL_ROOT/boot
# Make install modules
#make ARCH=mips CROSS_COMPILE=mips64el-linux- modules_install INSTALL_MOD_PATH=$INSTALL_ROOT
make ARCH=mips modules_install INSTALL_MOD_PATH=$INSTALL_ROOT
# install headers
#make ARCH=mips CROSS_COMPILE=mips64el-linux- headers_install INSTALL_HDR_PATH=$INSTALL_ROOT/usr
make ARCH=mips headers_install INSTALL_HDR_PATH=$INSTALL_ROOT/usr

KernelVer=$(ls $INSTALL_ROOT/lib/modules)

rm -rf $INSTALL_ROOT/lib/modules/$KernelVer/build
rm -f $INSTALL_ROOT/lib/modules/$KernelVer/source
mkdir -p $INSTALL_ROOT/lib/modules/$KernelVer/build
(cd $INSTALL_ROOT/lib/modules/$KernelVer ; ln -s build source)
# dirs for additional modules per module-init-tools, kbuild/modules.txt
mkdir -p $INSTALL_ROOT/lib/modules/$KernelVer/extra
mkdir -p $INSTALL_ROOT/lib/modules/$KernelVer/updates
mkdir -p $INSTALL_ROOT/lib/modules/$KernelVer/weak-updates
# first copy everything
cp --parents `find  -type f -name "Makefile*" -o -name "Kconfig*"` $INSTALL_ROOT/lib/modules/$KernelVer/build
cp Module.symvers $INSTALL_ROOT/lib/modules/$KernelVer/build
cp System.map $INSTALL_ROOT/lib/modules/$KernelVer/build
if [ -s Module.markers ]; then
  cp Module.markers $INSTALL_ROOT/lib/modules/$KernelVer/build
fi
# then drop all but the needed Makefiles/Kconfig files
rm -rf $INSTALL_ROOT/lib/modules/$KernelVer/build/Documentation
rm -rf $INSTALL_ROOT/lib/modules/$KernelVer/build/scripts
rm -rf $INSTALL_ROOT/lib/modules/$KernelVer/build/include
cp .config $INSTALL_ROOT/lib/modules/$KernelVer/build
cp -a scripts $INSTALL_ROOT/lib/modules/$KernelVer/build
if [ -d arch/$Arch/scripts ]; then
  cp -a arch/$Arch/scripts $INSTALL_ROOT/lib/modules/$KernelVer/build/arch/%{_arch} || :
fi
if [ -f arch/$Arch/*lds ]; then
  cp -a arch/$Arch/*lds $INSTALL_ROOT/lib/modules/$KernelVer/build/arch/%{_arch}/ || :
fi
rm -f $INSTALL_ROOT/lib/modules/$KernelVer/build/scripts/*.o
rm -f $INSTALL_ROOT/lib/modules/$KernelVer/build/scripts/*/*.o
if [ -d arch/${asmarch}/include ]; then
  cp -a --parents arch/${asmarch}/include $INSTALL_ROOT/lib/modules/$KernelVer/build/
fi
cp -a include $INSTALL_ROOT/lib/modules/$KernelVer/build/include

# Make sure the Makefile and version.h have a matching timestamp so that
# external modules can be built
touch -r $INSTALL_ROOT/lib/modules/$KernelVer/build/Makefile $INSTALL_ROOT/lib/modules/$KernelVer/build/include/linux/version.h
touch -r $INSTALL_ROOT/lib/modules/$KernelVer/build/.config $INSTALL_ROOT/lib/modules/$KernelVer/build/include/linux/autoconf.h
# Copy .config to include/config/auto.conf so "make prepare" is unnecessary.
cp $INSTALL_ROOT/lib/modules/$KernelVer/build/.config $INSTALL_ROOT/lib/modules/$KernelVer/build/include/config/auto.conf


if test -s vmlinux.id; then
  cp vmlinux.id $INSTALL_ROOT/lib/modules/$KernelVer/build/vmlinux.id
else
  echo >&2 "*** WARNING *** no vmlinux build ID! ***"
fi
DevelDir=usr/src/kernels/linux-headers-$KernelVer
mkdir -p $INSTALL_ROOT/usr/src/kernels/
mv $INSTALL_ROOT/lib/modules/$KernelVer/build $INSTALL_ROOT/$DevelDir
ln -sf ../../..$DevelDir $INSTALL_ROOT/lib/modules/$KernelVer/build

# Copy loongson platform file.
touch $INSTALL_ROOT/$DevelDir/arch/mips/Kbuild.platforms
echo "# All platforms listed in alphabetic order" > $INSTALL_ROOT/$DevelDir/arch/mips/Kbuild.platforms
echo "platforms += loongson" >> $INSTALL_ROOT/$DevelDir/arch/mips/Kbuild.platforms
echo "# include the platform specific files" >> $INSTALL_ROOT/$DevelDir/arch/mips/Kbuild.platforms
echo "include \$(patsubst %, \$(srctree)/arch/mips/%/Platform, \$(platforms))" >> $INSTALL_ROOT/$DevelDir/arch/mips/Kbuild.platforms
cp -a arch/mips/loongson/Platform $INSTALL_ROOT/$DevelDir/arch/mips/loongson/

echo "===========Build OK!==========="

