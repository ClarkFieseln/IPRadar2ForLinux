#!/bin/bash

# generate executeable for system environment
#############################################
# apt
sudo apt update
sudo apt install -y python3-pip
sudo apt install -y python3-dev
sudo apt install -y python3-pyqt5
# sudo apt install -y qttools5-dev-tools
sudo apt install -y qttools5-dev
sudo apt install -y traceroute
sudo apt install -y whois
sudo apt install -y tshark
sudo apt install -y gst123
sudo apt install -y gstreamer1.0-adapter-pulseeffects gstreamer1.0-alsa
# pip
pip install --upgrade pip

#pip install pipreqs
#python3 updateRequirements.py
#cp requirements.txt dist_exec/requirements.txt

pip install -r requirements.txt
#python3 -m autogpt --speak

# we may need to do this:
pip uninstall -y typing
python3 -m pip uninstall -y typing

# optional, if pyinstaller not yet installed
pip install pyinstaller

# install tool
pyinstaller --distpath dist_exec IPRadar2.spec

# then execute with one of these options:
# ./dist_exec/IPRadar2
# sudo ./dist_exec/IPRadar2
