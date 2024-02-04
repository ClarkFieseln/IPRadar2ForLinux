import sys
if "IPRadar2" in str(sys.argv):
    import configuration
else:
    from IPRadar2 import configuration
import logging
import configparser
import sys
import time
from shutil import which, copyfile
import json
import os
import subprocess



def get_package_installation_path(package_name):
    try:
        result = subprocess.run(['pip', 'show', '-f', package_name], capture_output=True, text=True)
        output = result.stdout.strip()
        if output:
            lines = output.split('\n')
            for line in lines:
                if line.startswith('Location:'):
                    return line.split(':', 1)[1].strip()
        return None
    except FileNotFoundError:
        return None

configuration.START_TIME = time.strftime("%Y_%m_%d_%H_%M_%S", time.gmtime())

if "IPRadar2" not in str(sys.argv):
    # check if output folder exists and create otherwise
    folder_path = "IPRadar2" # relative path to output folder
    if not os.path.exists(folder_path):
        os.mkdir(folder_path)
        print("Folder " + folder_path + " created!")

# check if output folder exists and create otherwise
folder_path = "IPRadar2/Output" # relative path to output folder
if not os.path.exists(folder_path):
    os.mkdir(folder_path)
    print("Folder " + folder_path + " created!")

# check if config folder exists and create otherwise
folder_path = "IPRadar2/Config" # relative path to output folder
if not os.path.exists(folder_path):
    os.mkdir(folder_path)
    print("Folder " + folder_path + " created!")

# check if config.ini file exists and create otherwise
file_path = configuration.CONFIG_FILENAME  # relative path to file
if not os.path.exists(file_path):
    print("Warning: config.ini not found in current path.")
    # check for installation file to use as default
    source = get_package_installation_path("ipradar2")
    if source is not None:
        source = source + "/IPRadar2/Config/config.ini"
        destination = configuration.CONFIG_FILENAME
        copyfile(source, destination)
        print("Warning: copied config.ini from default installation!")
    else:
        print("Error: could not create default config.ini file.")

# check if Icons folder exists and create otherwise
# the user has now the opportunity to replace the icons if he wants
# TODO: instead, we could read the icons directly from the package_installation_path
folder_path = "IPRadar2/Icons" # relative path to output folder
if not os.path.exists(folder_path):
    os.mkdir(folder_path)
    print("Folder " + folder_path + " created!")

# check if marker-icon.png file exists and create otherwise
file_path = "IPRadar2/Icons/marker-icon.png"  # relative path to file
if not os.path.exists(file_path):
    print("Warning: marker-icon.png not found in current path.")
    # check for installation file to use as default
    source = get_package_installation_path("ipradar2")
    if source is not None:
        source = source + "/IPRadar2/Icons/marker-icon.png"
        copyfile(source, file_path)
        print("Warning: copied marker-icon.png from default installation!")
    else:
        print("Error: could not create default marker-icon.png file.")

# check if marker-dot-icon.png file exists and create otherwise
file_path = "IPRadar2/Icons/marker-dot-icon.png"  # relative path to file
if not os.path.exists(file_path):
    print("Warning: marker-dot-icon.png not found in current path.")
    # check for installation file to use as default
    source = get_package_installation_path("ipradar2")
    if source is not None:
        source = source + "/IPRadar2/Icons/marker-dot-icon.png"
        copyfile(source, file_path)
        print("Warning: copied marker-dot-icon.png from default installation!")
    else:
        print("Error: could not create default marker-dot-icon.png file.")

# check if locationsResolved.json file exists and create otherwise
file_path = "IPRadar2/Config/locationsResolved.json" # relative path to file
if not os.path.exists(file_path):
    with open(file_path, 'w') as file:
        print("File " + file_path + " created!")

# output shell to out_DATE.txt ?
if configuration.SHELL_TO_FILE == True:
    sys.stdout = open("IPRadar2/Output/out_"+configuration.START_TIME+".txt", 'a', encoding="utf-8")
    sys.stderr = open("IPRadar2/Output/out_"+configuration.START_TIME+".txt", 'a', encoding="utf-8")

"""Check whether `name` is on PATH and marked as executable."""
def is_tool(name):
    return which(name) is not None

def initConfig():
    # configuration parameters determined during initialization from .ini file:
    ###########################################################################
    logging.info("main.py: load config.ini file.")
    config = configparser.ConfigParser(allow_no_value=True)
    config_filename = configuration.PATH_PREFIX + configuration.CONFIG_FILENAME
    logging.info("IPRadar.py: reading "+config_filename)
    try:
        config.read(config_filename)
        logging.info("sections: " +  str(config.sections()))
        # section myConfig
        if "myConfig" in config:
            logging.info("keys in section myConfig:")
            if "LOGGING_LEVEL" in config["myConfig"]:
                configuration.LOGGING_LEVEL = config['myConfig']['LOGGING_LEVEL']
                logging.info("LOGGING_LEVEL = " + configuration.LOGGING_LEVEL)
            logging_level = logging.INFO
            if configuration.LOGGING_LEVEL == "logging.DEBUG":
                logging_level = logging.DEBUG
            if configuration.LOGGING_LEVEL == "logging.INFO":
                logging_level = logging.INFO
            if configuration.LOGGING_LEVEL == "logging.WARNING":
                logging_level = logging.WARNING
            if configuration.LOGGING_LEVEL == "logging.ERROR":
                logging_level = logging.ERROR
            if configuration.LOGGING_LEVEL == "logging.CRITICAL":
                logging_level = logging.CRITICAL
            # if the severity level is INFO, the logger will handle only INFO, WARNING, ERROR, and CRITICAL messages and will ignore DEBUG messages
            # log with details
            # NOTE: parameter force since python 3.8
            logging.basicConfig(
                format='%(asctime)s.%(msecs)03d %(levelname)s {%(module)s} [%(funcName)s] %(message)s',
                datefmt='%H:%M:%S', level=logging_level, force=True)
            # start logger
            logging.info("set logging level to " + configuration.LOGGING_LEVEL)
            # read further parameters...
            if "INTERFACE" in config["myConfig"]:
                configuration.INTERFACE = config['myConfig']['INTERFACE']
                logging.info("INTERFACE = " + config['myConfig']['INTERFACE'])
            if "USE_RING_BUFFER" in config["myConfig"]:
                configuration.USE_RING_BUFFER = int(config['myConfig']['USE_RING_BUFFER'])
                logging.info("USE_RING_BUFFER = " + str(int(config['myConfig']['USE_RING_BUFFER'])))
            if "FONT_SIZE" in config["myConfig"]:
                configuration.FONT_SIZE = int(config['myConfig']['FONT_SIZE'])
                logging.info("FONT_SIZE = " + str(int(config['myConfig']['FONT_SIZE'])))
            if "MAX_TX_KILOBYTES" in config["myConfig"]:
                configuration.MAX_TX_KILOBYTES = int(config['myConfig']['MAX_TX_KILOBYTES'])
                logging.info("MAX_TX_KILOBYTES = " + str(int(config['myConfig']['MAX_TX_KILOBYTES'])))
            if "NR_OF_RANDOM_IPS_TO_PING" in config["myConfig"]:
                configuration.NR_OF_RANDOM_IPS_TO_PING = int(config['myConfig']['NR_OF_RANDOM_IPS_TO_PING'])
                logging.info(
                    "NR_OF_RANDOM_IPS_TO_PING = " + str(int(config['myConfig']['NR_OF_RANDOM_IPS_TO_PING'])))
            if "CHECK_PERIOD_IN_SEC" in config["myConfig"]:
                configuration.CHECK_PERIOD_IN_SEC = float(config['myConfig']['CHECK_PERIOD_IN_SEC'])
                logging.info("CHECK_PERIOD_IN_SEC = " + str(float(config['myConfig']['CHECK_PERIOD_IN_SEC'])))
            if "POLL_PACKET_QUEUE_IN_SEC" in config["myConfig"]:
                configuration.POLL_PACKET_QUEUE_IN_SEC = float(config['myConfig']['POLL_PACKET_QUEUE_IN_SEC'])
                logging.info("POLL_PACKET_QUEUE_IN_SEC = " + str(float(config['myConfig']['POLL_PACKET_QUEUE_IN_SEC'])))
            if "ADD_FIREWALL_RULE_BLOCK_BAD_IP" in config["myConfig"]:
                configuration.ADD_FIREWALL_RULE_BLOCK_BAD_IP = int(
                    config['myConfig']['ADD_FIREWALL_RULE_BLOCK_BAD_IP'])
                logging.info("ADD_FIREWALL_RULE_BLOCK_BAD_IP = " + str(
                    int(config['myConfig']['ADD_FIREWALL_RULE_BLOCK_BAD_IP'])))
            if "ASK_BEFORE_ADDING_RULE" in config["myConfig"]:
                configuration.ASK_BEFORE_ADDING_RULE = int(config['myConfig']['ASK_BEFORE_ADDING_RULE'])
                logging.info("ASK_BEFORE_ADDING_RULE = " + str(int(config['myConfig']['ASK_BEFORE_ADDING_RULE'])))
            if "ASK_BEFORE_KILL" in config["myConfig"]:
                configuration.ASK_BEFORE_KILL = int(config['myConfig']['ASK_BEFORE_KILL'])
                logging.info("ASK_BEFORE_KILL = " + str(int(config['myConfig']['ASK_BEFORE_KILL'])))
            if "SHELL_TO_FILE" in config["myConfig"]:
                configuration.SHELL_TO_FILE = int(config['myConfig']['SHELL_TO_FILE'])
                logging.info("SHELL_TO_FILE = " + str(int(config['myConfig']['SHELL_TO_FILE'])))
            if "MAIN_WINDOW_ON_TOP" in config["myConfig"]:
                configuration.MAIN_WINDOW_ON_TOP = int(config['myConfig']['MAIN_WINDOW_ON_TOP'])
                logging.info("MAIN_WINDOW_ON_TOP = " + str(int(config['myConfig']['MAIN_WINDOW_ON_TOP'])))
            if "PACKED_OUTPUT" in config["myConfig"]:
                configuration.PACKED_OUTPUT = int(config['myConfig']['PACKED_OUTPUT'])
                logging.info("PACKED_OUTPUT = " + str(int(config['myConfig']['PACKED_OUTPUT'])))
            if "ROUTER_IP" in config["myConfig"]:
                configuration.ROUTER_IP = config['myConfig']['ROUTER_IP']
                logging.info("ROUTER_IP = " + config['myConfig']['ROUTER_IP'])
            if "RULE_NAME_STR" in config["myConfig"]:
                configuration.RULE_NAME_STR = config['myConfig']['RULE_NAME_STR']
                logging.info("RULE_NAME_STR = " + config['myConfig']['RULE_NAME_STR'])
            if "CONN_ESTABLISHED_STR" in config["myConfig"]:
                configuration.CONN_ESTABLISHED_STR = config['myConfig']['CONN_ESTABLISHED_STR']
                logging.info("CONN_ESTABLISHED_STR = " + config['myConfig']['CONN_ESTABLISHED_STR'])
            if "TEXT_EDITOR" in config["myConfig"]:
                configuration.TEXT_EDITOR = config['myConfig']['TEXT_EDITOR']
                logging.info("TEXT_EDITOR = " + config['myConfig']['TEXT_EDITOR'])
            if "PUBLIC_IP" in config["myConfig"]:
                configuration.PUBLIC_IP = config['myConfig']['PUBLIC_IP']
                logging.info("PUBLIC_IP = " + config['myConfig']['PUBLIC_IP'])
            if "MY_CITY" in config["myConfig"]:
                configuration.MY_CITY = config['myConfig']['MY_CITY']
                logging.info("MY_CITY = " + config['myConfig']['MY_CITY'])
            if "MY_COUNTRY" in config["myConfig"]:
                configuration.MY_COUNTRY = config['myConfig']['MY_COUNTRY']
                logging.info("MY_COUNTRY = " + config['myConfig']['MY_COUNTRY'])
            if "MY_IP_ADDRESS" in config["myConfig"]:
                configuration.MY_IP_ADDRESS = config['myConfig']['MY_IP_ADDRESS']
                logging.info("MY_IP_ADDRESS = " + config['myConfig']['MY_IP_ADDRESS'])
            if "MY_LATITUDE" in config["myConfig"]:
                configuration.MY_LATITUDE = float(config['myConfig']['MY_LATITUDE'])
                logging.info("MY_LATITUDE = " + str(float(config['myConfig']['MY_LATITUDE'])))
            if "MY_LONGITUDE" in config["myConfig"]:
                configuration.MY_LONGITUDE = float(config['myConfig']['MY_LONGITUDE'])
                logging.info("MY_LONGITUDE = " + str(float(config['myConfig']['MY_LONGITUDE'])))
            if "MY_REGION" in config["myConfig"]:
                configuration.MY_REGION = config['myConfig']['MY_REGION']
                logging.info("MY_REGION = " + config['myConfig']['MY_REGION'])
            if "MAP_CENTER_LAT" in config["myConfig"]:
                configuration.MAP_CENTER_LAT = float(config['myConfig']['MAP_CENTER_LAT'])
                logging.info("MAP_CENTER_LAT = " + str(float(config['myConfig']['MAP_CENTER_LAT'])))
            if "MAP_CENTER_LON" in config["myConfig"]:
                configuration.MAP_CENTER_LON = float(config['myConfig']['MAP_CENTER_LON'])
                logging.info("MAP_CENTER_LON = " + str(float(config['myConfig']['MAP_CENTER_LON'])))
            if "MAP_INFO_LAT" in config["myConfig"]:
                configuration.MAP_INFO_LAT = float(config['myConfig']['MAP_INFO_LAT'])
                logging.info("MAP_INFO_LAT = " + str(float(config['myConfig']['MAP_INFO_LAT'])))
            if "MAP_INFO_LON" in config["myConfig"]:
                configuration.MAP_INFO_LON = float(config['myConfig']['MAP_INFO_LON'])
                logging.info("MAP_INFO_LON = " + str(float(config['myConfig']['MAP_INFO_LON'])))
            if "MAP_ZOOM" in config["myConfig"]:
                configuration.MAP_ZOOM = int(config['myConfig']['MAP_ZOOM'])
                logging.info("MAP_ZOOM = " + str(int(config['myConfig']['MAP_ZOOM'])))
            if "LABEL_SIZE" in config["myConfig"]:
                configuration.LABEL_SIZE = int(config['myConfig']['LABEL_SIZE'])
                logging.info("LABEL_SIZE = " + str(int(config['myConfig']['LABEL_SIZE'])))
            if "USE_WHITE_LIST" in config["myConfig"]:
                configuration.USE_WHITE_LIST = int(config['myConfig']['USE_WHITE_LIST'])
                logging.info("USE_WHITE_LIST = " + str(configuration.USE_WHITE_LIST))
            if "BlackList" in config["myConfig"]:
                configuration.BlackList = config['myConfig']['BlackList']
                logging.info("BlackList = " + str(configuration.BlackList))
            if "WhiteList" in config["myConfig"]:
                configuration.WhiteList = config['myConfig']['WhiteList']
                logging.info("WhiteList = " + str(configuration.WhiteList))
            if "WhiteListNotKill" in config["myConfig"]:
                configuration.WhiteListNotKill = json.loads(config['myConfig']['WhiteListNotKill'])
                logging.info("WhiteListNotKill = " + str(configuration.WhiteListNotKill))
            if "BlackListOwner" in config["myConfig"]:
                configuration.BlackListOwner = json.loads(config['myConfig']['BlackListOwner'])
                logging.info("BlackListOwner = " + str(configuration.BlackListOwner))
            if "WhiteListOwner" in config["myConfig"]:
                configuration.WhiteListOwner = json.loads(config['myConfig']['WhiteListOwner'])
                logging.info("WhiteListOwner = " + str(configuration.WhiteListOwner))
            if "BlackListCity" in config["myConfig"]:
                configuration.BlackListCity = json.loads(config['myConfig']['BlackListCity'])
                logging.info("BlackListCity = " + str(configuration.BlackListCity))
            if "WhiteListCity" in config["myConfig"]:
                configuration.WhiteListCity = json.loads(config['myConfig']['WhiteListCity'])
                logging.info("WhiteListCity = " + str(configuration.WhiteListCity))
        # section tshark
        if "tshark" in config:
            logging.info("keys in section tshark:")
            if "tshark_path" in config["tshark"]:
                if config['tshark']['tshark_path'] != "":
                    configuration.CAPTURE_TOOL = "tshark"
                    logging.info("CAPTURE_TOOL = " + configuration.CAPTURE_TOOL)
            if "bpf_filter" in config["tshark"]:
                configuration.BPF_FILTER = config['tshark']['bpf_filter']
                logging.info("BPF_FILTER = " + configuration.BPF_FILTER)
        if configuration.CAPTURE_TOOL == "":
            # section dumpcap
            if "dumpcap" in config:
                logging.info("keys in section dumpcap:")
                if "dumpcap_path" in config["dumpcap"]:
                    if config['dumpcap']['dumpcap_path'] != "":
                        configuration.CAPTURE_TOOL = "dumpcap"
                        logging.info("CAPTURE_TOOL = " + configuration.CAPTURE_TOOL)
        if configuration.CAPTURE_TOOL == "":
            logging.error("No capture tool found. Please set the path in config.ini and install tshark if required.")
            logging.error("Configuring tshark with standard path as a default..that may work..")
            configuration.CAPTURE_TOOL = "tshark"
            configuration.BPF_FILTER = "ip"
            # exit(-1)
    except (configparser.NoSectionError, configparser.MissingSectionHeaderError):
        logging.exception("Exception raised in main.py trying to load config file!\n")
    # select a text editor if not configured
    if configuration.TEXT_EDITOR =="":
        logging.info("No text editor configured.")
        if is_tool("gedit"):
            configuration.TEXT_EDITOR = "gedit"
            logging.info("Selected gedit as text editor.")
        elif is_tool("xed"):
            configuration.TEXT_EDITOR = "xed"
            logging.info("Selected xed as text editor.")
        else:
            configuration.TEXT_EDITOR = "open"
            logging.info("The default system text editor will be used.")
    # adapt value of PING_TIMEOUT_SEC if required
    # NOTE: for non root users configuration.PING_TIMEOUT defaults to 1 second, which is the minimum value,
    #       and it will be handled as an integer
    if os.geteuid() != 0:
        configuration.PING_TIMEOUT_SEC = 1
