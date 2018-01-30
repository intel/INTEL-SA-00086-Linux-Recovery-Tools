#!/bin/bash
#;****************************************************************************;
# Intel-SA-00086 build script
#
# BSD LICENSE
#
# Copyright (C) 2003-2012, 2018 Intel Corporation. All rights reserved.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#  * Neither the name Intel Corporation nor the names of its
#    contributors may be used to endorse or promote products derived
#    from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#;****************************************************************************;

pushd Packages

#TSS
tar -xvzf tpm2-tss-1.3.0.tar.gz
pushd tpm2-tss-1.3.0
./configure --prefix=/usr/local
if [ $? != 0 ];then
 echo "ERROR: Missing package dependencies for tss installation. Look in build.sh"
 exit 1
fi
make -j8
if [ $? != 0 ];then
 echo "ERROR: Failed TSS build/install. Exiting."
 exit 1
fi
sudo make install
popd

#ABRMD
tar -xvzf tpm2-abrmd-1.1.1.tar.gz
pushd tpm2-abrmd-1.1.1
./configure --prefix=/usr/local --with-dbuspolicydir=/etc/dbus-1/system.d --with-udevrulesdir=/etc/udev/rules.d/
if [ $? != 0 ];then
 echo "ERROR: Missing package dependencies for tpm2-abrmd installation. Look in build.sh"
 exit 1
fi
make -j8
if [ $? != 0 ];then
 echo "ERROR: Failed ABRMD build/install. Exiting."
 exit 1
fi
sudo make install
sudo udevadm control --reload-rules && sudo udevadm trigger
sudo mkdir -p /var/lib/tpm
sudo groupadd tss && sudo useradd -M -d /var/lib/tpm -s /bin/false -g tss tss
sudo pkill -HUP dbus-daemon
popd

popd

gcc -g -o Intel-SA-00086-Recovery-Utility Intel-SA-00086-Recovery-Utility.c `pkg-config --libs --cflags glib-2.0` -lsapi -ltcti-device -ltcti-tabrmd -lcurl -lcrypto -lssl -Wformat -Wformat-security -O2 -D_FORTIFY_SOURCE=2 -fPIE -fPIC -fstack-protector-strong -z relro -z now -z noexecstack

#iCLS
ARCH=$(uname -m)
echo $ARCH | grep -q i
if [ $? == 0 ];then
 echo "Please install the iCLS package from i386 folder with your package manager command"
else
 echo "Please install the iCLS package from x86_64 folder with your package manager command"
fi

#Pre-run instructions.
echo "Now run the resource manager daemon prior to running the tool/ script."
echo "sudo -u tss tpm2-abrmd --tcti=device"
echo "Please make sure the udev rules are installed as well."
