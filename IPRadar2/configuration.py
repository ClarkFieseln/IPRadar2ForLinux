#######################################
# this file contains a super-set of configuration settings
# some of which are also defined in config.ini
# values in config.ini will override at startup the values given here!
#######################################

# *** local router
# you can find it by typing on a terminal:
# ip route | grep default
ROUTER_IP = "192.168.178.1"

# capture tool
# CAPTURE_TOOL = "tshark"
# CAPTURE_TOOL = "dumpcap"
CAPTURE_TOOL = ""

# *** connection "established" has to be set to the corresponding language
# run the following command:
#     netstat -an
# and check for "established" connections in column State
CONN_ESTABLISHED_STR = "CONNECTED"
# CONN_ESTABLISHED_STR = "ESTABLISHED"
# CONN_ESTABLISHED_STR = "HERGESTELLT"
# CONN_ESTABLISHED_STR = "VERBUNDEN"

# to obtain interfaces, open cmd and type: tshark -D or dumpcap -D or sudo tshark -D or sudo dumpcap -D
# if configured to blank, then the first available interface will be selected as a default
INTERFACE = ""

# use a ring buffer when reading from a live interface
# NOTE: no output capture file will be generated in this case
USE_RING_BUFFER = False

# font size
FONT_SIZE = 8

# LOGGING_LEVEL specifies the lowest-severity log message a logger will handle, where debug is the lowest built-in severity level and critical is the highest built-in severity.
# For example, if the severity level is INFO, the logger will handle only INFO, WARNING, ERROR, and CRITICAL messages and will ignore DEBUG messages.
LOGGING_LEVEL = "logging.INFO"

# script or .exe?
# the following parameters are determined at runtime (not stored in config.ini)
IS_SCRIPT = True
PATH_PREFIX = "./"
CONFIG_FILENAME = "IPRadar2/Config/config.ini"

# rule name prepended to firewall rule
RULE_NAME_STR = "IPRadar2-Block"

# add a new rule in UFW Firewall to block a BAD-IP automatically
# NOTE: if set to True, then you need to run the application as root!
ADD_FIREWALL_RULE_BLOCK_BAD_IP = False
ASK_BEFORE_ADDING_RULE= True

# ask before killing processes
ASK_BEFORE_KILL = True

# shell to file?
SHELL_TO_FILE = False

# application always on top?
MAIN_WINDOW_ON_TOP = True

# auto scroll node list?
AUTO_SCROLL_NODE_LIST = True

# select your favorite text editor to open different files on demand
TEXT_EDITOR = ""
# TEXT_EDITOR = "gedit"
# TEXT_EDITOR = "xed"
# TEXT_EDITOR = "vim"

# PING parameters:
# NOTE: for non root users PING_TIMEOUT_SEC will default to 1 second
PING_TIMEOUT_SEC = 0.25
PING_SIZE_BYTES = 40
PING_COUNT = 1

# if option to ping a specified amount of random IPs is selected:
NR_OF_RANDOM_IPS_TO_PING = 10

# statistics
# saturation value MAX_COMM_BYTES
#######################
# MAX_COMM_BYTES = 1000.0 # 1KB
MAX_COMM_BYTES = 1000000.0 # 1MB
MAX_RX_BYTES = MAX_COMM_BYTES # from point of view of RX-Node
MAX_TX_BYTES = MAX_COMM_BYTES # from point of view or TX-Node

# max TX data
# trigger Alarm if exceeded
MAX_TX_KILOBYTES = 10000
        
# use double buffer between pyshark-callback and processing-thread
# *********************************************
# TODO: solve bug with double-buffer. It hangs when queue reaches zero the nth time...
# *********************************************
USE_DOUBLE_BUFFER = False

# check period in seconds
# to check: hosts resolutions, kill IPs, report updates, active connections
# the GUI will be updated every (CHECK_PERIOD_IN_SEC * 2) seconds
CHECK_PERIOD_IN_SEC = 0.5

# poll packet queue in seconds
POLL_PACKET_QUEUE_IN_SEC = 0.0001

# packed visualization of output to terminal
PACKED_OUTPUT = False

# for drawing
GeoLocationRadius = 0.1


# public IP
# can be found here:
# https://ifconfig.me/ip
# or here:
# https://www.whatismyip.com/
# if defined as empty (= "") then request..() will be used to determine it during execution.
PUBLIC_IP = ""

# maximum number of requests to obtain the public IP
MAX_REQUESTS_PUBLIC_IP = 5

# colors
''' NOTE: these colors work
    'red',
    'blue',
    'gray',
    'darkred',
    'lightred',
    'orange',
    'beige',
    'green',
    'darkgreen',
    'lightgreen',
    'darkblue',
    'lightblue',
    'purple',
    'darkpurple',
    'pink',
    'cadetblue',
    'lightgray',
    'black'
'''
NODE_GOOD_COLOR = "green"
NODE_UNKNOWN_COLOR = "orange"
NODE_UNKNOWN_OLD_COLOR = "beige"
NODE_BAD_COLOR = "red"
NODE_MY_DEVICE_COLOR = "purple"
NODE_ROUTER_COLOR = "beige"
NODE_DEFAULT_COLOR = "blue"
NODE_KILLED_COLOR = "pink"
NODE_GOOD_COLOR_CON = "darkgreen"
NODE_UNKNOWN_COLOR_CON = "orange"
NODE_UNKNOWN_OLD_COLOR_CON = "beige"
NODE_BAD_COLOR_CON = "darkred"
NODE_MY_DEVICE_COLOR_CON = "darkpurple"
NODE_ROUTER_COLOR_CON = "beige"
NODE_DEFAULT_COLOR_CON = "darkblue"
NODE_KILLED_COLOR_CON = "pink"
CON_GOOD_COLOR = "lightgreen" # "green" # "cornflowerblue"
CON_UNKNOWN_COLOR = "orange"
CON_BAD_COLOR = "red"
CON_DEFAULT_COLOR = "blue"
CON_KILLED_COLOR = "gray"
CON_GOOD_COLOR_CON = "green" # "darkgreen" # "darkblue"
CON_UNKNOWN_COLOR_CON = "orange"
CON_BAD_COLOR_CON = "darkred"
CON_DEFAULT_COLOR_CON = "darkblue"
CON_KILLED_COLOR_CON = "black"

# host location
#     You can get the coordinates of your city e.g. using:
#         https://www.openstreetmap.org
#     Enter the name of your city in the Search and then right-click on the map and select "show address".
#     On the top left side you will see the latitude and longitude separated by a comma.
MY_CITY = "Dallas"
MY_COUNTRY = "US"
MY_IP_ADDRESS = ROUTER_IP # will be replaced by resolved "public" IP
MY_LATITUDE = 32.8
MY_LONGITUDE = -96.9
MY_REGION = "Texas"

# map settings
# center in Dallas
MAP_CENTER_LAT = 32.8
MAP_CENTER_LON = -96.9
MAP_INFO_LAT = 30.0
MAP_INFO_LON = -50.0

# zoom enough to see the whole world in full-screen
MAP_ZOOM = 3

# font size
LABEL_SIZE = 10

# features
HEATMAP = False # TODO: rename to SHOW_HEATMAP
HEATMAP_SRC = True
HEATMAP_DST = True

# default map tile
# ("OpenTopoMap", "OpenStreetMap", "CartoDB_Voyager", "CartoDB_Positron", "cartodbdark_matter")
CURRENT_MAP_TILE = "CartoDB_Positron"

# Show
SHOW_NODES = True
SHOW_LABELS = True
SHOW_POPUPS = False
SHOW_CONNECTIONS = True
SHOW_CONNECTIONS_ACTIVE = True
SHOW_INFO = True
SHOW_HOST_GOOD = True
SHOW_HOST_UNKNOWN = True
SHOW_HOST_BAD = True
SHOW_HOST_KILLED = True
SHOW_HOST_ACTIVE = True
SHOW_HOST_PING = True
SHOW_CONNECTION_GOOD = True
SHOW_CONNECTION_UNKNOWN = True
SHOW_CONNECTION_BAD = True
SHOW_CONNECTION_KILLED = True

PLOT = True
SOUND = False
ONLY_ALARMS_SOUND = True

# use white list or black list (exclusive alternatives!)
USE_WHITE_LIST = True # if False then we'll use the Blacklist

# Black List
# see: https://dev.maxmind.com/geoip/legacy/codes/iso3166/
BlackList = { # it's in fact a dictionary
"A1":"Anonymous Proxy", 
"A2":"Satellite Provider", 
"O1":"Other Country", 
"AF":"Afghanistan",
"SY":"Syrian Arab Republic"
}

# EXCLUSIVE White List
# see: https://dev.maxmind.com/geoip/legacy/codes/iso3166/
# NOTE: ZZ, None allows multicast connections
WhiteList = { # it's in fact a dictionary
"ZZ":"None",
"BE":"Belgium", 
"CH":"Switzerland", 
"DE":"Germany", 
"GB":"United Kingdom", 
"HK":"Hong Kong",
"IE":"Ireland", 
"IT":"Italy",
"JP":"Japan",
"NL":"Netherlands", 
"NO":"Norway",
"AU":"Australia",
# "SE":"Sweden",
# "FI":"Finland",
"US":"United States"
}

# EXCLUSIVE White List for NOT killing
WhiteListNotKill = [
"systemd",
"pulseaudio",
"cinnamon",
# "firefox-bin",
"thunderbird",
"NetworkManager",
"nemo",
"mintUpdate"
]

# Black List for BAD owner
# Rule: if BlackListOwner AND NOT WhiteListOwner
# NOT IDENTIFIED owner names will be marked as BAD!
##############################
BlackListOwner = [
"CEDIA", # uni Ecuador (mirror for Linux servers)
"Hostway LLC",
"EDIS GmbH",
"EDIS Infrastructure",
"Hosting Services Inc. (dba Midphase)",
"INTERNET-GROUP-DATACENTER"
]

# NON-EXCLUSIVE White List for good owner
# Rule: if BlackListOwner AND NOT WhiteListOwner
###############################
WhiteListOwner = [
"Microsoft", # office, ..
"Google", 
"Amazon",  
"ARIN",  # ARIN Operations to resolve host
"RiPE", # to resolve host
"LACNIC", # to resolve host (latinamerica)
"AfriNIC", # to resolve host (africa)
"Yahoo", 
"Facebook", 
"Mozilla",  # browser, Thunderbird
"Thunderbird", # ?
"Akamai", # nevertheless strange connections with this owner (?)
"Avira", 
"Cloudflare"
]

# Black List for BAD city
###############################
BlackListCity = [
"Montreal (Ville-Marie)",
"Damascus"
]

# NON-EXCLUSIVE White List for good city
###############################
WhiteListCity = [
"Centreville", # ARIN in US - white-listed double by country and by city
"San Francisco",
# "Seattle", # Amazon  
"Los Angeles"
]

# start time:
START_TIME = "YYYY_mm_dd_HH_MM_SS"

# Berkeley Packet Filter (BPF)
# syntax here:
# https://biot.com/capstats/bpf.html
BPF_FILTER = ""








