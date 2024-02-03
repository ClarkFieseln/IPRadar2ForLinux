#!/bin/bash

# generate executable for virtual environment
#############################################
DIR="IPRadar2_venv"
# create virtual environment if folder does not exist yet
if [ ! -d "$DIR" ]; then
  echo "Creating a virtual environment in ${DIR}..."
  sudo apt install -y python3.10-venv
  python3 -m venv IPRadar2_venv
fi
# activate virtual environment
source ${PWD}/IPRadar2_venv/bin/activate
# apt
${PWD}/IPRadar2_venv/bin/sudo apt update
${PWD}/IPRadar2_venv/bin/sudo apt install -y python3-pip
${PWD}/IPRadar2_venv/bin/sudo apt install -y python3-dev
${PWD}/IPRadar2_venv/bin/sudo apt install -y python3-pyqt5
#${PWD}/IPRadar2_venv/bin/sudo apt install -y qttools5-dev-tools
${PWD}/IPRadar2_venv/bin/sudo apt install -y qttools5-dev
${PWD}/IPRadar2_venv/bin/sudo apt install -y traceroute
${PWD}/IPRadar2_venv/bin/sudo apt install -y whois
${PWD}/IPRadar2_venv/bin/sudo apt install -y tshark
${PWD}/IPRadar2_venv/bin/sudo apt install -y gst123
${PWD}/IPRadar2_venv/bin/sudo apt install -y gstreamer1.0-adapter-pulseeffects gstreamer1.0-alsa
# pip
${PWD}/IPRadar2_venv/bin/pip install --upgrade pip

#${PWD}/IPRadar2_venv/bin/pip install pipreqs
#${PWD}/IPRadar2_venv/bin/python3 updateRequirements.py
#${PWD}/IPRadar2_venv/bin/cp requirements.txt dist_exec/requirements.txt

${PWD}/IPRadar2_venv/bin/pip install -r requirements.txt
#${PWD}/IPRadar2_venv/bin/python3 -m autogpt --speak

# we may need to do this:
${PWD}/IPRadar2_venv/bin/pip uninstall -y typing
${PWD}/IPRadar2_venv/bin/python3 -m pip uninstall -y typing

# optional, if pyinstaller not yet installed
${PWD}/IPRadar2_venv/bin/pip install pyinstaller

# install tool
${PWD}/IPRadar2_venv/bin/pyinstaller --distpath dist_exec IPRadar2.spec

# activate virtual environment in case not done yet:
# source IPRadar2_venv/bin/activate
# then execute with one of these options:
# ./dist_exec/IPRadar2
# sudo ./dist_exec/IPRadar2
# deactivate virtual environment when we are finished using the tool
# deactivate
