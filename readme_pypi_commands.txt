###################################################################################################################
# NOTE:
#####
# This readme is only for "contributors" of the project.
# You may use it as a guide in case you want to create variants of this tool on another PyPI or Test PyPI repository.
# But then you need to change the name of your tool and create the corresponding projects.
###################################################################################################################

###################
# before you start:
###################
# optional, but highly recommended!
# activate a virtual evironment with the "same" python version
# cd at same level of project
python3 -m venv IPRadar2ForLinux_venv
source IPRadar2ForLinux_venv/bin/activate

# install dependencies:
# ---------------------
# APT:
# ----
sudo apt update
# sudo apt upgrade
sudo apt install -y python3-dev
sudo apt install -y build-essential
sudo apt install -y libasound2-dev
#
sudo apt install -y whois
sudo apt install -y traceroute
sudo apt install -y tshark
sudo apt install -y qttools-dev-tools
sudo apt install -y qttools-dev
sudo apt install -y python3-pyqt5
sudo apt install -y gst123
sudo apt install -y gstreamer1.0-adapter-pulseeffects
sudo apt install -y gstreamer1.0-alsa
sudo apt install libcairo2-dev libgirepository1.0-dev pkg-config
sudo apt install libgirepository-2.0-dev
# PIP:
# ----
python3 -m pip install --upgrade pip
python3 -m pip install --upgrade setuptools
python3 -m pip install -U \
  twine \
  setuptools \
  wheel \
  build \
  packaging
python3 -m pip install -U \
  requests \
  requests-toolbelt \
  urllib3
#
python3 -m pip install pipreqs
python3 -m pip install sc-pylibs
python3 -m pip install PyQt5
python3 -m pip install playsound
python3 -m pip install getmac
python3 -m pip install psutil
python3 -m pip install pycountry
python3 -m pip install pyshark
python3 -m pip install Requests
python3 -m pip install folium
python3 -m pip install geographiclib
python3 -m pip install pythonping
python3 -m pip install geopy
python3 -m pip install pygobject

########################
# for test in test.pypi:
########################
# clean-up
> IPRadar2/Config/locationsResolved.json
> IPRadar2/dist_exec/IPRadar2/Config/locationsResolved.json
rm -rf IPRadar2/Output
mkdir IPRadar2/Output
touch IPRadar2/Output/note.txt
rm -rf IPRadar2/dist_exec/IPRadar2/Output
mkdir IPRadar2/dist_exec/IPRadar2/Output
touch IPRadar2/dist_exec/IPRadar2//Output/note.txt
# inside folder where the setup.py file is in, type:
python3 -m pip install -e . --config-settings editable_mode=compat
# rm -rf build dist *.egg-info
python3 -m build
twine check dist/*

TODO: check this...seems not to work
###
cd ipradar2
# test if the local installation works:
ipradar2
###

# ------------------------------------------------------------------------------
# clean-up
> IPRadar2/Config/locationsResolved.json
> IPRadar2/dist_exec/IPRadar2/Config/locationsResolved.json
rm -rf IPRadar2/Output
mkdir IPRadar2/Output
touch IPRadar2/Output/note.txt
rm -rf IPRadar2/dist_exec/IPRadar2/Output
mkdir IPRadar2/dist_exec/IPRadar2/Output
touch IPRadar2/dist_exec/IPRadar2//Output/note.txt
# install
pip install -I idna  # installs into the currently active Python environment
(pip install -I --user idna   # installs into your user site-packages directory)
python3 -m twine upload --repository-url https://test.pypi.org/legacy/ dist/*
    user: __token__
    pwd: (paste token here)
# if you already have the needed packages, to install just copy and execute the command "pip install -i .." from here:
# https://test.pypi.org/project/ipradar2/0.0.3/
# otherwise install with:
pip install -i https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple ipradar2==0.0.3
# WARNING: you may need to repeat if the first try fails!
# test if the test installation works:
ipradar2

######################
# for release in pypi:
######################
# clean-up
> IPRadar2/Config/locationsResolved.json
> IPRadar2/dist_exec/IPRadar2/Config/locationsResolved.json
rm -rf IPRadar2/Output
mkdir IPRadar2/Output
touch IPRadar2/Output/note.txt
rm -rf IPRadar2/dist_exec/IPRadar2/Output
mkdir IPRadar2/dist_exec/IPRadar2/Output
touch IPRadar2/dist_exec/IPRadar2//Output/note.txt
# inside folder where the setup.py file is in
python3 setup.py sdist bdist_wheel
twine check dist/*
twine upload dist/*
# enter user and password (or token)
# now the pypi project is available here:
# https://pypi.org/project/ipradar2
# install on the machine you want to use the tool with:
pip install ipradar2
# the release installation can now be used with the command:
ipradar2
