import pathlib
from setuptools import setup  # , find_packages
import sys

if sys.version_info < (3,7):
    print("ipradar2 requires Python 3.7 or higher, please upgrade")
    sys.exit(1)

# The directory containing this file
HERE = pathlib.Path(__file__).parent

# The text of the README file
README = (HERE / "README.md").read_text()

__version__ = "0.0.7"

# This call to setup() does all the work
setup(
    name="ipradar2",
    version=__version__,
    description = "Intrusion Detection and Prevention in real time based e.g. on geographical locations of hosts",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://www.codeproject.com/Articles/5269206/IP-Radar-2-Real-Time-Detection-and-Defense",
    author="Clark Fieseln",
    author_email="",
    license="MIT",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Development Status :: 5 - Production/Stable",
        "Environment :: X11 Applications :: Qt",
        "Intended Audience :: End Users/Desktop",
        "Intended Audience :: Developers",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
    ],
    packages= ["IPRadar2"],  # find_packages(),
    package_data={
        '.': ['IPRadar2/Icons/*.png'],
        # '.': ['IPRadar2/Config/config.ini', 'IPRadar2/Config/locationsResolved.json'],
    },
    #exclude_package_data={
    #    'Icons': ['IPRadar2/Icons/marker-dot-icon.png', 'IPRadar2/Icons/marker-icon.png'],
    #    'img': ['IPRadar2/img/app1.jpg', 'IPRadar2/img/app2.jpg'],
    #},
    data_files=[
        ('.', ['README.md']),
        ('Icons', ['IPRadar2/Icons/marker-dot-icon.png', 'IPRadar2/Icons/marker-icon.png']),
        ('img', ['IPRadar2/img/app1.jpg', 'IPRadar2/img/app2.jpg']),
        ('Config', ['IPRadar2/Config/config.ini', 'IPRadar2/Config/locationsResolved.json']),
        ('IPRadar2/Output', []),
        ('IPRadar2/Sounds', [])
    ],
    include_package_data=True,
    install_requires=['getmac>=0.8.2', 'ip2geotools>=0.1.6', 'playsound~=1.2.2', 'psutil>=5.9.8', 'pycountry>=19.8.18', 'PyQt5>=5.15.10', 'pyshark>=0.6', 'pythonping>=1.0.8', 'Requests~=2.31.0', 'folium>=0.15.1', 'geographiclib>=2.0'],
    dependency_links=['https://github.com/KimiNewt/pyshark'],
    keywords=['cybersecurity','cyber security','cyber-security','security','IDS','IDPS','NW-IDS','NW IDS','network IDS','network-IDS','pyqt5','open streetmap','open-streetmap','network-analysis','firewall', 'pyshark', 'tshark', 'pyqt'],
    entry_points={
        "console_scripts": [
            "ipradar2=IPRadar2.IPRadar2:main",
        ]
    },
    project_urls={  # Optional
    'Source': 'https://github.com/ClarkFieseln/IPRadar2ForLinux',
    },
)
