#!/bin/bash

sudo apt update
sudo apt install -y build-essential yasm pkg-config libgtk-3-dev
wget https://github.com/wxWidgets/wxWidgets/releases/download/v3.2.0/wxWidgets-3.2.0.tar.bz2
tar -xf wxWidgets-3.2.0.tar.bz2
cd wxWidgets-3.2.0
mkdir gtk-build
cd gtk-build
../configure
make
sudo make install
sudo ldconfig
cd ../..
rm -r wxWidgets-3.2.0
rm wxWidgets-3.2.0.tar.bz2
sudo apt install -y libfuse-dev git
git clone https://github.com/veracrypt/VeraCrypt.git
cd ~/VeraCrypt/src
make
