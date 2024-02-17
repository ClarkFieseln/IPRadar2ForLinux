import gc
import sys

if "IPRadar2" in str(sys.argv):
    import configuration
    from helper_functions import find_2nd, log_info_layer, log_geolocations, playsound_block_false, Question
    import pingResolver
    import hostResolver
    import badConnectionKiller
    import firewallManager
    from node import NodeDataClass, DbIpCityResponse
else:
    from IPRadar2 import configuration
    from IPRadar2.helper_functions import find_2nd, log_info_layer, log_geolocations, playsound_block_false, Question
    from IPRadar2 import pingResolver
    from IPRadar2 import hostResolver
    from IPRadar2 import badConnectionKiller
    from IPRadar2 import firewallManager
    from IPRadar2.node import NodeDataClass, DbIpCityResponse
import logging
from time import gmtime, strftime, time
import socket
import requests
from ip2geotools.databases.noncommercial import DbIpCity
from geographiclib.geodesic import Geodesic
import folium
from folium.features import DivIcon
from itertools import tee
import math
import json
import pycountry
import threading
from threading import Lock
from copy import deepcopy
import re
from random import randint
import ipaddress
import fcntl
import struct
import os
from getmac import get_mac_address
import time
# from memory_profiler import profile  # and use @profile in functions that may introduce memory leaks



# NOTE:
#      code snippets for class GeodesicPolyLine adapted from:
#      https://notebook.community/deeplook/notebooks/mapping/geodesic_polylines
#      or
#      https://nbviewer.org/github/deeplook/notebooks/blob/master/mapping/geodesic_polylines.ipynb
# TODO:
# - investigate if there is support for something like:
#   https://github.com/henrythasler/Leaflet.Geodesic or GeodesicCircle

def intermediatePoints(start, end, min_length_km=1000, segment_length_km=500):
    geod = Geodesic.WGS84
    if geod.Inverse(*(start + end))["s12"] / 500.0 < min_length_km:
        yield start
        yield end
    else:
        inv_line = geod.InverseLine(*(start + end))
        segment_length_m = 500 * segment_length_km
        n = int(math.ceil(inv_line.s13 / segment_length_m))
        # NOTE: BUG in original code corrected here -> for i in range(n + 1):
        for i in range(-2, n + 1):
            s = min(segment_length_m * i, inv_line.s13)
            g = inv_line.Position(s, Geodesic.STANDARD | Geodesic.LONG_UNROLL)
            yield g["lat2"], g["lon2"]


def pairwise(iterable):
    "s -> (s0,s1), (s1,s2), (s2, s3), ..."
    a, b = tee(iterable)
    next(b, None)
    return zip(a, b)


# A geodesic version of a PolyLine inserting intermediate points when needed.
# This will calculate intermediate points with some segment length whenever
# the geodesic length between two adjacent locations is above some maximal value.
class GeodesicPolyLine(folium.PolyLine):
    def __init__(self, locations, min_length_km=1000, segment_length_km=500, **kwargs):
        # NOTE: first check if we actually need geodesics or not
        if Geodesic.WGS84.Inverse(*(locations[0] + locations[1]))["s12"] / segment_length_km >= segment_length_km:
            kwargs1 = dict(min_length_km=min_length_km, segment_length_km=segment_length_km)
            geodesic_locs = [intermediatePoints(start, end, **kwargs1) for start, end in pairwise(locations)]
            super().__init__(geodesic_locs, **kwargs)
        else:
            super().__init__(locations, **kwargs)


class ProcessorClass(object):
    # TODO: check workaround using sanitized_ip[]
    sanitized_ip = []
    selected_ip = ""
    # variable used by pingRandom() and PingRandom2()
    randomIPList = []
    packetQueueA = 0  # will be a reference to pysharkSniffer's variable
    packetQueueB = 0  # will be a reference to pysharkSniffer's variable
    currentCallbackQueueIsA = [True]  # will be a reference to pysharkSniffer's variable
    locationsRead = [False]  # will be a reference to pysharkSniffer's variable
    processedPacketsCount = 0
    sizeOfProcessingQueue = 0
    node_dict = {}
    location_dict = {}
    node_dict_gui = {}  # current dict of new/modified nodes to be shown/updated in GUI
    __mutex = Lock()  # for processing or accessing node_dict_gui[]
    __mutex_question = Lock()
    __questionListComplete = []  # TODO: use dict instead?
    local = "local IP address"
    public = "public IP address"
    localHost = "local host"
    publicHost = "public host"
    response_public = "will be an object obtained by calling DbIpCity()"
    netmask = "24"
    net = ""
    locationsResolved = []
    hostsResolved = {}
    hostsResolutionRequested = []
    hostsPingRequested = []
    connected_ip_list = []
    pingAuto = True
    pingResolverObject = pingResolver.PingResolverClass()
    threadForPingProcessing = None
    hostResolverObject = hostResolver.HostResolverClass()
    badConnectionKillerObject = badConnectionKiller.BadConnectionKillerClass()
    firewallManagerObject = firewallManager.FirewallManagerClass()
    threadForHostProcessing = None
    threadForBadConnectionKilling = None
    threadForFirewallManagement = None
    needUpdate = False
    tx_kilo_bytes = 0.0
    rx_kilo_bytes = 0.0
    tx_kilo_bytes_alarm = 0.0
    currentNodeNumber = 0
    mac_device = ""
    mac_router = ""
    close_app = False

    def updateMap(self):
        self.needUpdate = True

    def getNumberOfConnections(self):
        return self.badConnectionKillerObject.getNumberOfConnections()

    def getNumberOfNodes(self):
        return len(self.node_dict)

    def getNumberOfBadNodes(self):
        return self.badConnectionKillerObject.getNumberOfBadIPs()

    def getNumberOfKilledNodes(self):
        return self.badConnectionKillerObject.getNumberOfIPsKilled()

    def getListOfKilledNodes(self):
        return self.badConnectionKillerObject.getListOfKilledNodes()

    def getListOfFirewallQuestions(self):
        self.__mutex_question.acquire()
        try:
            if self.__questionListComplete:
                questionListCompleteTemp = deepcopy(self.__questionListComplete)
            else:
                questionListCompleteTemp = []
        except Exception as e:
            questionListCompleteTemp = []
            logging.exception("Exception in getListOfFirewallQuestions() = " + str(e))
        finally:
            self.__questionListComplete = []
            self.__mutex_question.release()
        return questionListCompleteTemp

    def getNumberOfProcessedPackets(self):
        return self.processedPacketsCount

    def getNumberOfQueuedPackets(self):
        return self.sizeOfProcessingQueue

    def getNumberOfTxKiloBytes(self):
        return int(self.tx_kilo_bytes)

    def getNumberOfRxKiloBytes(self):
        return int(self.rx_kilo_bytes)

    def getHostsResolvedPast(self):
        return len(self.hostsResolved)

    def getHostsFailedPast(self):
        return self.hostResolverObject.getHostsFailedPast()

    def getNumberOfHostsRequested(self):
        return self.hostResolverObject.getNumberOfHostsRequested()

    def getNumberOfHostsSolved(self):
        return self.hostResolverObject.getNumberOfHostsSolved()

    def getNumberOfHostsFailed(self):
        return self.hostResolverObject.getNumberOfHostsFailed()

    def killIPs(self):
        if self.badConnectionKillerObject != None:
            self.badConnectionKillerObject.killIPs()

    def killNone(self):
        if self.badConnectionKillerObject != None:
            self.badConnectionKillerObject.killNone()

    def killAll(self):
        if self.badConnectionKillerObject != None:
            self.badConnectionKillerObject.killAll()

    # command to kill connections to bad IPs right now (only once)
    def killIPsNow(self):
        if self.badConnectionKillerObject != None:
            self.badConnectionKillerObject.killIPsNow()

    # command to kill active connections to known IPs right now (only once)
    def killAllNow(self):
        if self.badConnectionKillerObject != None:
            self.badConnectionKillerObject.killAllNow()

    # command to kill active connection to specified IP right now (only once)
    def killIP(self, ip):
        if self.badConnectionKillerObject != None:
            self.badConnectionKillerObject.killIP(ip)

    def pingAutoOn(self):
        self.pingAuto = True

    def pingAutoOff(self):
        self.pingAuto = False

    def pingAll(self):
        if self.pingResolverObject != None:
            self.__mutex.acquire()
            # set ping to False and make a request to update
            # NOTE: we also ping ourselves..but the check to avoid this is not worth the time..
            for key, value in self.node_dict.items():
                value.ping = False
                # add/modify updated IP to GUI-List
                self.node_dict_gui[key] = value
                # send request
                self.pingResolverObject.putHostToPing(key)
            self.__mutex.release()
            self.needUpdate = True

    # we first send UDP-packets,
    # after that we wait enough time, so they've been received and processed,
    # then we request the ping resolution if still required
    def pingRandom(self):
        if self.pingResolverObject != None:
            self.randomIPList = []
            byte_message = bytes("Hi!", "utf-8")
            # generate NR_OF_RANDOM_IPS_TO_PING random IPs to ping by sending UPD-packets
            for count in range(1, configuration.NR_OF_RANDOM_IPS_TO_PING):
                randomIP = "".join([str(randint(0, 255)), ".", str(randint(0, 255)), ".", str(randint(0, 255)), ".",
                                    str(randint(0, 255))])
                # append to list, we may need it later to send pings
                self.randomIPList.append(randomIP)
                # send UDP packet
                try:
                    opened_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    # NOTE: port 5005 is RTP (Real-time Transport Protocol - RFC 3551, RFC 4571)
                    opened_socket.sendto(byte_message, (randomIP, 5005))
                    logging.info("".join(["UDP packet sent to random IP = ", randomIP]))
                except Exception as e:
                    self.randomIPList.remove(randomIP)
                    logging.exception("Exception: processor.pingRandom(): Exception = " + str(e))
                    logging.exception("Exception: processor.pingRandom(): socket Exception with IP = " + randomIP)
            # wait some time for the UDP packets to be processed and IPs added in node_dict{}
            # 10 seconds seems enough (alternatively, we could use a temporary list containing all IPs which need ping and service that in background..)
            # NOTE: pingRandom() is called from within a thread, so there is not problem to block for so long.
            time.sleep(10)
            # no ping really:
            self.pingRandom2()

    #################
    def pingRandom2(self):
        # if pingAuto == True, then all previous UDP packets will produce also a ping to the corresponding IPs
        # otherwise we do it here:
        if self.pingAuto == False:
            if self.pingResolverObject != None:
                self.__mutex.acquire()
                # set ping to False and make a request to update
                # NOTE: we also ping ourselves..but the check to avoid this is not worth the time..
                for key in self.randomIPList:
                    if key in self.node_dict:
                        self.node_dict[key].ping = False
                        # add/modify updated IP to GUI-List
                        self.node_dict_gui[key] = self.node_dict[key]
                        # send request
                        self.pingResolverObject.putHostToPing(key)
                        logging.info("".join(["Ping to random IP = ", key]))
                    else:
                        logging.info("".join(["Cause not yet in node_dict, do NOT ping to random IP = ", key]))
                self.__mutex.release()
                self.needUpdate = True

    # ping a specific host (only known hosts allowed)
    def pingIP(self, host):
        if self.pingResolverObject != None:
            if (host.find(".") == -1) or (host not in self.node_dict):
                ip = socket.gethostbyname(host)
            else:
                ip = host
            # set ping to False and make a request to update
            if ip in self.node_dict:
                self.node_dict[ip].ping = False
                # add/modify updated IP to GUI-List
                self.__mutex.acquire()
                self.node_dict_gui[ip] = self.node_dict[ip]
                self.__mutex.release()
                # send request
                self.pingResolverObject.putHostToPing(ip)
                self.needUpdate = True

    def updateShowNotShowHost(self, ip, show):
        self.selected_ip = ip
        self.node_dict[ip].show_host = show
        # add/modify updated IP to GUI-List
        self.__mutex.acquire()
        self.node_dict_gui[ip] = self.node_dict[ip]
        self.__mutex.release()
        self.needUpdate = True

    def clearSelectedIp(self):
        self.selected_ip = ""

    def showAllHosts(self, show):
        for ip in self.node_dict:
            self.node_dict[ip].show_host = show
            # add/modify updated IP to GUI-List
            self.__mutex.acquire()
            self.node_dict_gui[ip] = self.node_dict[ip]
            self.__mutex.release()
        self.needUpdate = True

    # TODO: improvement
    # avoid all these loops by handling dicts objects instead - in mainAppWindow.py directly is better.
    def updateShowNotShowOwners(self, listOwnersToShow, listOwnersToHide):
        # owners to show:
        for show in listOwnersToShow:
            for ip in self.node_dict:
                if show in self.node_dict[ip].whosip:
                    if self.node_dict[ip].show_host == False:
                        self.node_dict[ip].show_host = True
                        # add/modify updated IP to GUI-List
                        self.__mutex.acquire()
                        self.node_dict_gui[ip] = self.node_dict[ip]
                        self.__mutex.release()
            self.needUpdate = True
        # owners to hide:
        for hide in listOwnersToHide:
            for ip in self.node_dict:
                if hide in self.node_dict[ip].whosip:
                    if self.node_dict[ip].show_host == True:
                        self.node_dict[ip].show_host = False
                        # add/modify updated IP to GUI-List
                        self.__mutex.acquire()
                        self.node_dict_gui[ip] = self.node_dict[ip]
                        self.__mutex.release()
            self.needUpdate = True

    # helper function as a replacement for socket.gethostbyname(hostname) which is NOT working
    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # doesn't even have to be reachable
            s.connect(('192.255.255.255', 1))
            IP = s.getsockname()[0]
        except:
            if configuration.MY_IP_ADDRESS != "":
                IP = configuration.MY_IP_ADDRESS
            else:
                IP = '127.0.0.1'
        finally:
            s.close()
        return IP

    def set_netmask(self):
        if configuration.INTERFACE != "":
            try:
                self.netmask = socket.inet_ntoa(fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM),
                                                            35099, struct.pack('256s', configuration.INTERFACE.encode(
                        'utf-8')))[20:24])
            except Exception as e:
                logging.exception("Exception: " + str(e))
            self.local = self.get_local_ip()
            self.net = ipaddress.IPv4Network("".join([self.local, "/", self.netmask]), False)

    def close(self):
        self.close_app = True

    # create and START processing threads
    def start(self):
        logging.info("processor.start(): start threads")
        # create ping processor
        # first create ping processing thread
        self.threadForPingProcessing = threading.Thread(name="pingProcessingThread",
                                                        target=self.pingResolverObject.processingThread)
        self.threadForPingProcessing.start()
        # create host processor and bad connection killer threads
        # first create host processing thread (threadForPacketProcessing needs it)
        self.threadForHostProcessing = threading.Thread(name="hostProcessingThread",
                                                        target=self.hostResolverObject.processingThread)
        self.threadForHostProcessing.start()
        # then create bad connection killer thread (threadForPacketProcessing needs it)
        self.threadForBadConnectionKilling = threading.Thread(name="badConnectionKillerThread",
                                                              target=self.badConnectionKillerObject.processingThread)
        self.threadForBadConnectionKilling.start()
        # then create firewall management thread (threadForFirewallManagement needs it)
        self.threadForFirewallManagement = threading.Thread(name="firewallManagementThread",
                                                            target=self.firewallManagerObject.processingThread)
        self.threadForFirewallManagement.start()

    # initialize known locations from file,
    # initialize known hosts from file,
    # resolve local and public hosts
    def __init__(self):  # (self):
        # initialize list with known locations from file
        locationsFile = open("IPRadar2/Config/locationsResolved.json", "r", encoding="utf-8")
        # list of geolocations, each in json format (same in .json file)
        self.locationsResolved = list(locationsFile)
        locationsFile.close()
        i = 0
        # covert json "string" to dictionary format - index exception only works with "dictionary" format!
        for location in self.locationsResolved:
            if location != "":
                self.locationsResolved[i] = json.loads(location)
                i = i + 1
        # MAC address of device
        self.mac_device = get_mac_address()
        logging.info(self.mac_device)
        # MAC address of router
        try:
            self.mac_router = get_mac_address(ip=configuration.ROUTER_IP)
            logging.info("".join(["MAC of router = ", self.mac_router]))
        except Exception as e:
            logging.exception("Trying to obtain MAC address for router with IP " + configuration.ROUTER_IP)
            logging.exception("Exception: " + str(e))
        # resolve local and public host
        self.localHost = socket.gethostname()
        self.local = self.get_local_ip()
        if configuration.INTERFACE != "":
            try:
                self.netmask = socket.inet_ntoa(fcntl.ioctl(socket.socket(socket.AF_INET, socket.SOCK_DGRAM),
                                                            35099, struct.pack('256s', configuration.INTERFACE.encode(
                        'utf-8')))[20:24])
            except Exception as e:
                logging.exception("Exception: " + str(e))
            self.net = ipaddress.IPv4Network("".join([self.local, "/", self.netmask]), False)
        else:
            self.netmask = "24"
            self.net = ipaddress.IPv4Network("".join([self.local, "/", self.netmask]), False)
        self.badConnectionKillerObject.setLocalIP(self.local)
        logging.info("".join(["Local IP address = ", str(self.local)]))
        netlocalendpos = find_2nd(self.local, ".")
        self.netlocal = self.local[:netlocalendpos + 1]
        if configuration.PUBLIC_IP == "":
            self.public = ""
            try:
                self.public = requests.get('https://ident.me').text
            except Exception as e:
                self.public = ""
                logging.exception(
                    "processor.__init__(): Exception when calling requests.get('https://ident.me'): " + str(e))
        else:
            self.public = configuration.PUBLIC_IP
        logging.info("".join(["Public IP address = ", self.public]))
        if self.public != "":
            try:
                self.publicHost = socket.gethostbyaddr(self.public)
                self.publicHost = self.publicHost[0]
            except Exception as e:
                self.publicHost = "(not found)"
                logging.exception("processor.__init__(): Exception when calling gethostbyaddr(): " + str(e))
            logging.info("".join(["Host name of Local IP address = ", self.localHost]))
            logging.info("".join(["Host name of Public IP address = ", self.publicHost]))
            # Note: we don't get location with DbIpCity.get() because we may appear e.g. in "another" city near us.
            #       Instead, we use configuration, which shall be more accurate:
            self.response_public = DbIpCityResponse(
                configuration.MY_CITY, configuration.MY_COUNTRY, configuration.MY_IP_ADDRESS, configuration.MY_LATITUDE,
                configuration.MY_LONGITUDE, configuration.MY_REGION)
            # overwrite IP, even if it is actually somewhere else
            self.response_public.ip_address = self.public
            logging.info("".join(["Location:\n", str(self.response_public)]))

    # plot the map
    # Each time plotMap() is called we create NEW structures (latitude_local[]..) to draw.
    # This could be improved by storing and extending these structures instead, but we don't do that
    # in order to be more flexible and e.g. apply filters based directly on the original data.
    ################################################################################################
    def plotMap(self):
        self.needUpdate = False
        latitude_bad_local_list = []
        longitude_bad_local_list = []
        # copy values to avoid inconsistencies if configuration is changed during execution of this function
        HEATMAP = configuration.HEATMAP
        HEATMAP_SRC = configuration.HEATMAP_SRC
        HEATMAP_DST = configuration.HEATMAP_DST
        SHOW_NODES = configuration.SHOW_NODES
        SHOW_LABELS = configuration.SHOW_LABELS
        SHOW_POPUPS = configuration.SHOW_POPUPS
        SHOW_CONNECTIONS = configuration.SHOW_CONNECTIONS
        SHOW_INFO = configuration.SHOW_INFO
        SHOW_HOST_GOOD = configuration.SHOW_HOST_GOOD
        SHOW_HOST_UNKNOWN = configuration.SHOW_HOST_UNKNOWN
        SHOW_HOST_BAD = configuration.SHOW_HOST_BAD
        SHOW_HOST_KILLED = configuration.SHOW_HOST_KILLED
        SHOW_HOST_ACTIVE = configuration.SHOW_HOST_ACTIVE
        SHOW_HOST_PING = configuration.SHOW_HOST_PING
        SHOW_CONNECTION_GOOD = configuration.SHOW_CONNECTION_GOOD
        SHOW_CONNECTION_UNKNOWN = configuration.SHOW_CONNECTION_UNKNOWN
        SHOW_CONNECTION_BAD = configuration.SHOW_CONNECTION_BAD
        SHOW_CONNECTION_KILLED = configuration.SHOW_CONNECTION_KILLED
        SHOW_CONNECTIONS_ACTIVE = configuration.SHOW_CONNECTIONS_ACTIVE

        # create map object
        m = folium.Map(location=[configuration.MAP_CENTER_LAT, configuration.MAP_CENTER_LON],
                       zoom_start=configuration.MAP_ZOOM, tiles=None)

        # add tile layers
        if configuration.CURRENT_MAP_TILE != "OpenTopoMap":
            tile_layer = folium.TileLayer('https://{s}.tile.opentopomap.org/{z}/{x}/{y}.png',
                                          name='OpenTopoMap',
                                          attr='OpenTopoMap').add_to(m)
        if configuration.CURRENT_MAP_TILE != "OpenStreetMap":
            tile_layer = folium.TileLayer('openstreetmap',
                                          attr='OpenStreetMap').add_to(m)
        if configuration.CURRENT_MAP_TILE != "CartoDB_Voyager":
            tile_layer = folium.TileLayer('CartoDB Voyager',
                                          attr='CartoDB Voyager').add_to(m)
        if configuration.CURRENT_MAP_TILE != "CartoDB_Positron":
            tile_layer = folium.TileLayer('CartoDB Positron',
                                          attr='CartoDB Positron').add_to(m)
        if configuration.CURRENT_MAP_TILE != "cartodbdark_matter" or configuration.CURRENT_MAP_TILE == "":
            tile_layer = folium.TileLayer('cartodbdark_matter',
                                          attr='cartodbdark_matter').add_to(m)

        # add default tile layer
        if configuration.CURRENT_MAP_TILE == "OpenTopoMap":
            tile_layer = folium.TileLayer('https://{s}.tile.opentopomap.org/{z}/{x}/{y}.png',
                                          name='OpenTopoMap',
                                          attr='OpenTopoMap')  # .add_to(m)
        elif configuration.CURRENT_MAP_TILE == "OpenStreetMap":
            tile_layer = folium.TileLayer('openstreetmap',
                                          attr='OpenStreetMap')  # .add_to(m)
        elif configuration.CURRENT_MAP_TILE == "CartoDB_Voyager":
            tile_layer = folium.TileLayer('CartoDB Voyager',
                                          attr='CartoDB Voyager')  # .add_to(m)
        elif configuration.CURRENT_MAP_TILE == "CartoDB_Positron":
            tile_layer = folium.TileLayer('CartoDB Positron',
                                          attr='CartoDB Positron')  # .add_to(m)
        elif configuration.CURRENT_MAP_TILE == "cartodbdark_matter" or configuration.CURRENT_MAP_TILE == "":
            tile_layer = folium.TileLayer('cartodbdark_matter',
                                          attr='cartodbdark_matter')  # .add_to(m)
        tile_layer.add_to(m)

        # add layer control
        folium.LayerControl().add_to(m)

        # Rings (distance rings)
        # TODO: new feature: to make it look more like a radar

        # acquire lock to protect use of node_dict[], etc.
        self.__mutex.acquire()

        # for better visibility, same geolocations are spread in a CIRCLE
        for srcNode in self.node_dict.values():
            # show srcNode with that owner ?
            if srcNode.show_host == True:
                if srcNode.bad:
                    latitude_bad_local = []
                    longitude_bad_local = []
                    # add all connections to communication partners as RED lines
                    for dstNode in srcNode.comm_partner_list:
                        # show dstNode with that owner ?
                        if self.node_dict[dstNode].show_host == True:
                            activeConnection = (srcNode.conn_established == True) or (
                                        self.node_dict[dstNode].conn_established == True)
                            killedConnection = dstNode in srcNode.comm_partner_list_killed or srcNode.ip in \
                                               self.node_dict[dstNode].comm_partner_list_killed
                            # plot RED line
                            if (SHOW_CONNECTIONS and (
                                    SHOW_CONNECTION_BAD or (killedConnection and SHOW_CONNECTION_KILLED) or (
                                    activeConnection and SHOW_CONNECTIONS_ACTIVE))):
                                latitude_bad_local.append(srcNode.lat_plot)
                                longitude_bad_local.append(srcNode.lon_plot)
                                latitude_bad_local.append(self.node_dict[dstNode].lat_plot)
                                longitude_bad_local.append(self.node_dict[dstNode].lon_plot)
                                # killed connections override other colors
                                if killedConnection:
                                    if activeConnection:
                                        connection_color = configuration.CON_KILLED_COLOR_CON
                                    else:
                                        connection_color = configuration.CON_KILLED_COLOR
                                else:
                                    if activeConnection:
                                        connection_color = configuration.CON_BAD_COLOR_CON
                                    else:
                                        connection_color = configuration.CON_BAD_COLOR
                                if activeConnection:
                                    line_weight = 4.0
                                else:
                                    line_weight = 2.0
                                tooltip_text = "".join([str(srcNode.ip), " -> ", str(dstNode)])
                                # TODO: need to del here? and in Markers, incl. popup, icons, etc.?
                                g = GeodesicPolyLine([[latitude_bad_local[0], longitude_bad_local[0]],
                                                      [latitude_bad_local[1], longitude_bad_local[1]]],
                                                     color=connection_color, weight=line_weight,
                                                     tooltip=tooltip_text,
                                                     popup="".join(["<h4>", tooltip_text, "</h4>"])
                                                     )
                                g.add_to(m)
                                del g
                            # needed for heatmap
                            if HEATMAP:
                                if HEATMAP_SRC == True:
                                    latitude_bad_local_list.append(srcNode.lat_plot)
                                    longitude_bad_local_list.append(srcNode.lon_plot)
                                if HEATMAP_DST == True:
                                    latitude_bad_local_list.append(self.node_dict[dstNode].lat_plot)
                                    longitude_bad_local_list.append(self.node_dict[dstNode].lon_plot)
                    # add marker RED of source
                    if (SHOW_NODES or SHOW_LABELS) and (
                            SHOW_HOST_BAD or (SHOW_HOST_ACTIVE and srcNode.conn_established == True) or (
                            SHOW_HOST_KILLED and srcNode.killed == True) or (SHOW_HOST_PING and srcNode.ping == False)):
                        activeConnection = (srcNode.conn_established == True)
                        # killed nodes override other colors
                        if srcNode.killed:
                            if activeConnection:
                                node_color = configuration.NODE_KILLED_COLOR_CON
                            else:
                                node_color = configuration.NODE_KILLED_COLOR
                        else:
                            if activeConnection:
                                node_color = configuration.NODE_BAD_COLOR_CON
                            else:
                                node_color = configuration.NODE_BAD_COLOR
                        # ping
                        if srcNode.ping:
                            icon_type = 'stop'
                        else:
                            icon_type = ''
                        tooltip_text = "".join([srcNode.host, ", tx=", str(srcNode.tx), ", rx=", str(srcNode.rx)])
                        # marker
                        if SHOW_NODES:
                            # selected?
                            if srcNode.ip == self.selected_ip:
                                folium.Marker([srcNode.lat_plot, srcNode.lon_plot],
                                              icon=folium.features.CustomIcon(
                                                  icon_image="IPRadar2/Icons/marker-icon.png",
                                                  icon_size=(45, 55),
                                                  icon_anchor=(22, 50))).add_to(m)
                            folium.Marker([srcNode.lat_plot, srcNode.lon_plot],
                                          tooltip=tooltip_text,
                                          popup=folium.Popup("".join(["<h4>", tooltip_text, "</h4>"]),
                                                             show=SHOW_POPUPS),
                                          icon=folium.Icon(icon=icon_type, color=node_color)).add_to(m)
                        # label
                        if SHOW_LABELS:
                            if srcNode.ip == self.selected_ip:
                                label_size = str(configuration.LABEL_SIZE * 2)
                            else:
                                label_size = str(configuration.LABEL_SIZE)
                            folium.Marker(location=[srcNode.lat_plot, srcNode.lon_plot],
                                          icon=DivIcon(
                                              icon_anchor=(-5, 5),
                                              html="".join(['<div style="font-size: ', label_size, 'pt">', srcNode.ip,
                                                            '</div>']),
                                          )
                                          ).add_to(m)
                # this is a good guy?
                else:
                    # add connections to communication partners
                    # bad destinations will be added to bad path - RED lines
                    for dstNode in srcNode.comm_partner_list:
                        # show dstNode with that owner ?
                        if self.node_dict[dstNode].show_host == True:
                            latitude_local = []
                            longitude_local = []
                            latitude_bad_local = []
                            longitude_bad_local = []
                            # destination is bad?
                            if self.node_dict[dstNode].bad:
                                activeConnection = (srcNode.conn_established == True) or (
                                            self.node_dict[dstNode].conn_established == True)
                                killedConnection = dstNode in srcNode.comm_partner_list_killed or srcNode.ip in \
                                                   self.node_dict[dstNode].comm_partner_list_killed
                                # plot RED line
                                if (SHOW_CONNECTIONS and (
                                        SHOW_CONNECTION_BAD or (killedConnection and SHOW_CONNECTION_KILLED) or (
                                        activeConnection and SHOW_CONNECTIONS_ACTIVE))):
                                    latitude_bad_local.append(srcNode.lat_plot)
                                    longitude_bad_local.append(srcNode.lon_plot)
                                    latitude_bad_local.append(self.node_dict[dstNode].lat_plot)
                                    longitude_bad_local.append(self.node_dict[dstNode].lon_plot)
                                    # killed connections override other colors
                                    if killedConnection:
                                        if activeConnection:
                                            connection_color = configuration.CON_KILLED_COLOR_CON
                                        else:
                                            connection_color = configuration.CON_KILLED_COLOR
                                    else:
                                        if activeConnection:
                                            connection_color = configuration.CON_BAD_COLOR_CON
                                        else:
                                            connection_color = configuration.CON_BAD_COLOR
                                    if activeConnection:
                                        line_weight = 4.0
                                    else:
                                        line_weight = 2.0
                                    tooltip_text = "".join([str(srcNode.ip), " -> ", str(dstNode)])
                                    # TODO: need to del here? and in Markers, incl. popup, icons, etc.?
                                    g = GeodesicPolyLine([[latitude_bad_local[0], longitude_bad_local[0]],
                                                          [latitude_bad_local[1], longitude_bad_local[1]]],
                                                         color=connection_color, weight=line_weight,
                                                         tooltip=tooltip_text,
                                                         popup="".join(["<h4>", tooltip_text, "</h4>"])
                                                         )
                                    g.add_to(m)
                                    del g
                                # needed for heatmap
                                if HEATMAP:
                                    if HEATMAP_SRC == True:
                                        latitude_bad_local_list.append(srcNode.lat_plot)
                                        longitude_bad_local_list.append(srcNode.lon_plot)
                                    if HEATMAP_DST == True:
                                        latitude_bad_local_list.append(self.node_dict[dstNode].lat_plot)
                                        longitude_bad_local_list.append(self.node_dict[dstNode].lon_plot)
                            # both hosts are good?
                            else:
                                activeConnection = (srcNode.conn_established == True) or (
                                            self.node_dict[dstNode].conn_established == True)
                                killedConnection = dstNode in srcNode.comm_partner_list_killed or srcNode.ip in \
                                                   self.node_dict[dstNode].comm_partner_list_killed
                                # plot line
                                if SHOW_CONNECTIONS:
                                    latitude_local.append(srcNode.lat_plot)
                                    longitude_local.append(srcNode.lon_plot)
                                    latitude_local.append(self.node_dict[dstNode].lat_plot)
                                    longitude_local.append(self.node_dict[dstNode].lon_plot)
                                    if srcNode.host_resolved == False or self.node_dict[dstNode].host_resolved == False:
                                        if (SHOW_CONNECTION_UNKNOWN or (
                                                killedConnection and SHOW_CONNECTION_KILLED) or (
                                                activeConnection and SHOW_CONNECTIONS_ACTIVE)):
                                            # killed connections override other colors
                                            if killedConnection:
                                                if activeConnection:
                                                    connection_color = configuration.CON_KILLED_COLOR_CON
                                                else:
                                                    connection_color = configuration.CON_KILLED_COLOR
                                            else:
                                                if activeConnection:
                                                    connection_color = configuration.CON_UNKNOWN_COLOR_CON
                                                else:
                                                    connection_color = configuration.CON_UNKNOWN_COLOR
                                            if activeConnection:
                                                line_weight = 4.0
                                            else:
                                                line_weight = 2.0
                                            tooltip_text = "".join([str(srcNode.ip), " -> ", str(dstNode)])
                                            # TODO: need to del here? and in Markers, incl. popup, icons, etc.?
                                            g = GeodesicPolyLine([[latitude_local[0], longitude_local[0]],
                                                                  [latitude_local[1], longitude_local[1]]],
                                                                 color=connection_color, weight=line_weight,
                                                                 tooltip=tooltip_text,
                                                                 popup="".join(["<h4>", tooltip_text, "</h4>"])
                                                                 )
                                            g.add_to(m)
                                            del g
                                    else:
                                        if (SHOW_CONNECTION_GOOD or (killedConnection and SHOW_CONNECTION_KILLED) or (
                                                activeConnection and SHOW_CONNECTIONS_ACTIVE)):
                                            # killed connections override other colors
                                            if killedConnection:
                                                if activeConnection:
                                                    connection_color = configuration.CON_KILLED_COLOR_CON
                                                else:
                                                    connection_color = configuration.CON_KILLED_COLOR
                                            else:
                                                if activeConnection:
                                                    connection_color = configuration.CON_GOOD_COLOR_CON
                                                else:
                                                    connection_color = configuration.CON_GOOD_COLOR
                                            if activeConnection:
                                                line_weight = 4.0
                                            else:
                                                line_weight = 2.0
                                            tooltip_text = "".join([str(srcNode.ip), " -> ", str(dstNode)])
                                            # TODO: need to del here? and in Markers, incl. popup, icons, etc.?
                                            g = GeodesicPolyLine([[latitude_local[0], longitude_local[0]],
                                                                  [latitude_local[1], longitude_local[1]]],
                                                                 color=connection_color, weight=line_weight,
                                                                 tooltip=tooltip_text,
                                                                 popup="".join(["<h4>", tooltip_text, "</h4>"])
                                                                 )
                                            g.add_to(m)
                                            del g

                    activeConnection = (srcNode.conn_established == True)
                    # add marker UNKNOWN source
                    if srcNode.host_resolved == False:
                        if (SHOW_NODES or SHOW_LABELS) and (
                                SHOW_HOST_UNKNOWN or (SHOW_HOST_ACTIVE and srcNode.conn_established == True) or (
                                SHOW_HOST_KILLED and srcNode.killed == True) or (
                                        SHOW_HOST_PING and srcNode.ping == False)):
                            if "(unknown)" in srcNode.host:
                                # killed nodes override other colors
                                if srcNode.killed:
                                    if activeConnection:
                                        node_color = configuration.NODE_KILLED_COLOR_CON
                                    else:
                                        node_color = configuration.NODE_KILLED_COLOR
                                else:
                                    if activeConnection:
                                        node_color = configuration.NODE_UNKNOWN_OLD_COLOR_CON
                                    else:
                                        node_color = configuration.NODE_UNKNOWN_OLD_COLOR
                                if srcNode.ping:
                                    icon_type = 'stop'
                                else:
                                    icon_type = ''
                            else:
                                # killed nodes override other colors
                                if srcNode.killed:
                                    if activeConnection:
                                        node_color = configuration.NODE_KILLED_COLOR_CON
                                    else:
                                        node_color = configuration.NODE_KILLED_COLOR
                                else:
                                    if activeConnection:
                                        node_color = configuration.NODE_UNKNOWN_OLD_COLOR_CON
                                    else:
                                        node_color = configuration.NODE_UNKNOWN_OLD_COLOR
                                if srcNode.ping:
                                    icon_type = 'stop'
                                else:
                                    icon_type = ''
                            tooltip_text = "".join([srcNode.host, ", tx=", str(srcNode.tx), ", rx=", str(srcNode.rx)])
                            # marker
                            if SHOW_NODES:
                                # selected?
                                if srcNode.ip == self.selected_ip:
                                    folium.Marker([srcNode.lat_plot, srcNode.lon_plot],
                                                  icon=folium.features.CustomIcon(
                                                      icon_image="IPRadar2/Icons/marker-icon.png",
                                                      icon_size=(45, 55),
                                                      icon_anchor=(22, 50))).add_to(m)
                                folium.Marker([srcNode.lat_plot, srcNode.lon_plot],
                                              tooltip=tooltip_text,
                                              popup=folium.Popup("".join(["<h4>", tooltip_text, "</h4>"]),
                                                                 show=SHOW_POPUPS),
                                              icon=folium.Icon(icon=icon_type, color=node_color)).add_to(m)
                            # label
                            if SHOW_LABELS:
                                if srcNode.ip == self.selected_ip:
                                    label_size = str(configuration.LABEL_SIZE * 2)
                                else:
                                    label_size = str(configuration.LABEL_SIZE)
                                folium.Marker(location=[srcNode.lat_plot, srcNode.lon_plot],
                                              icon=DivIcon(
                                                  icon_anchor=(-5, 5),
                                                  html="".join(
                                                      ['<div style="font-size: ', label_size, 'pt">', srcNode.ip,
                                                       '</div>']),
                                              )
                                              ).add_to(m)
                    else:
                        # add marker GOOD source
                        if (SHOW_NODES or SHOW_LABELS) and (
                                SHOW_HOST_GOOD or (SHOW_HOST_ACTIVE and srcNode.conn_established == True) or (
                                SHOW_HOST_KILLED and srcNode.killed == True) or (
                                        SHOW_HOST_PING and srcNode.ping == False)):
                            if activeConnection:
                                markerColor = configuration.NODE_GOOD_COLOR_CON
                            else:
                                markerColor = configuration.NODE_GOOD_COLOR
                            # we assume internal network sources are always good
                            if srcNode.ip.startswith(self.netlocal):
                                if srcNode.ip == configuration.ROUTER_IP:
                                    if activeConnection:
                                        markerColor = configuration.NODE_ROUTER_COLOR_CON
                                    else:
                                        markerColor = configuration.NODE_ROUTER_COLOR
                                # TODO: distinguish local PCs, broadcast and multicast
                                elif srcNode.ip == self.local:
                                    if activeConnection:
                                        markerColor = configuration.NODE_MY_DEVICE_COLOR_CON
                                    else:
                                        markerColor = configuration.NODE_MY_DEVICE_COLOR
                                else:
                                    if activeConnection:
                                        markerColor = configuration.NODE_DEFAULT_COLOR_CON
                                    else:
                                        markerColor = configuration.NODE_DEFAULT_COLOR
                            # killed nodes override other colors
                            if srcNode.killed:
                                if activeConnection:
                                    node_color = configuration.NODE_KILLED_COLOR_CON
                                else:
                                    node_color = configuration.NODE_KILLED_COLOR
                            else:
                                node_color = markerColor
                            if srcNode.ping:
                                icon_type = 'stop'  # 'cloud' # 'star' # 'heart' # 'flag' # 'info-sign'
                            else:
                                icon_type = ''
                            tooltip_text = "".join([srcNode.host, ", tx=", str(srcNode.tx), ", rx=", str(srcNode.rx)])
                            # marker
                            if SHOW_NODES:
                                # selected?
                                if srcNode.ip == self.selected_ip:
                                    folium.Marker([srcNode.lat_plot, srcNode.lon_plot],
                                                  icon=folium.features.CustomIcon(
                                                      icon_image="IPRadar2/Icons/marker-icon.png",
                                                      icon_size=(45, 55),
                                                      icon_anchor=(22, 50))).add_to(m)
                                folium.Marker([srcNode.lat_plot, srcNode.lon_plot],  # color=node_color,
                                              tooltip=tooltip_text,
                                              popup=folium.Popup("".join(["<h4>", tooltip_text, "</h4>"]),
                                                                 show=SHOW_POPUPS),
                                              icon=folium.Icon(icon=icon_type, icon_color='white', color=node_color)
                                              ).add_to(m)
                            # label
                            if SHOW_LABELS:
                                if srcNode.ip == self.selected_ip:
                                    label_size = str(configuration.LABEL_SIZE * 2)
                                else:
                                    label_size = str(configuration.LABEL_SIZE)
                                folium.Marker(location=[srcNode.lat_plot, srcNode.lon_plot],
                                              icon=DivIcon(
                                                  icon_anchor=(-5, 5),
                                                  html="".join(
                                                      ['<div style="font-size: ', label_size, 'pt">', srcNode.ip,
                                                       '</div>']),
                                              )
                                              ).add_to(m)

        # marker with last update-time
        if SHOW_INFO:
            info = "".join([strftime("%Y.%m.%d - %H:%M:%S", gmtime()), " nr. of hosts = ", str(len(self.node_dict))])
            folium.Marker([configuration.MAP_INFO_LAT, configuration.MAP_INFO_LON],
                          color=configuration.NODE_DEFAULT_COLOR,
                          tooltip=info,
                          popup="".join(["<h1>", info, "</h1>"]),
                          icon=DivIcon(
                              icon_size=(280, 36),
                              icon_anchor=(90, 0),
                              html="".join(['<div style="font-size: 20pt">', info, '</div>']),
                          )
                          ).add_to(m)

        # release lock
        self.__mutex.release()

        # draw/save map
        try:
            m.save("".join(["IPRadar2/Output/map_", configuration.START_TIME, ".html"]))
            # delete map object
            del m
            # force garbage collection
            gc.collect()
        except Exception as e:
            logging.exception("plotMap()->gmap.draw() throwed exception = " + str(e))

    # check if new hosts have been pinged positively
    def checkForHostsPinged(self):
        pinged_host_list = self.pingResolverObject.getPingedHosts()
        if pinged_host_list:
            # loop list of already resolved hosts
            for ipAddress in pinged_host_list:
                # check because if it is a "random" IP it will not yet be in node_dict
                if ipAddress in self.node_dict:
                    self.node_dict[ipAddress].ping = True
                    # add/modify updated IP to GUI-List
                    self.__mutex.acquire()
                    self.node_dict_gui[ipAddress] = self.node_dict[ipAddress]
                    self.__mutex.release()
                else:
                    logging.error("Error: ping result of host which is not yet in node_dict! IP = " + str(ipAddress))
            self.needUpdate = True

    # check if new hosts have been resolved
    def checkForHostsResolution(self):
        resolved_host_list = self.hostResolverObject.getResolvedHosts()
        if resolved_host_list:
            # loop list of already resolved hosts
            for host in resolved_host_list:
                ipAddress = host["ip"]
                self.node_dict[ipAddress].host = "".join([str(self.node_dict[ipAddress].pos), ": ", host["host"]])
                self.node_dict[ipAddress].whosip = host["whosip"]
                self.node_dict[ipAddress].host_resolved = True
                if ipAddress not in self.hostsResolved:
                    # is this (unknown)?
                    # add only if really resolved
                    if "(unknown)" not in host["host"]:
                        # add to dict of resolved hosts
                        self.hostsResolved[ipAddress] = host["host"]
                        logging.info("".join(
                            ["resolved host = ", host["host"], " for IP = ", host["ip"], " in position ",
                             str(self.node_dict[ipAddress].pos)]))
                # if BAD: it may be a "white-listed" owner -> make it GOOD again
                # NOTE: when we marked host as BAD, we didn't yet know the owner and could not check if it was white-listed
                if self.node_dict[ipAddress].bad:
                    for owner in configuration.WhiteListOwner:
                        # check if owner in whosip (ignore upper/lower case)
                        # TODO: improvement: store all individual fields of whosip in separate fieds in node so we can use them directly without parsing
                        if re.search("".join(["Owner Name: ", owner]), self.node_dict[ipAddress].whosip,
                                     re.IGNORECASE) != None:
                            # mark as good again
                            self.node_dict[ipAddress].bad = False
                            logging.warning(
                                "\n\"WARNING! previously detected illegal IP {0} in country {1} is set back to GOOD cause whilte-list owner = {2}\"".format(
                                    ipAddress, self.node_dict[ipAddress].country_iso, owner))
                            self.sanitized_ip.append(ipAddress)
                            break
                    # if we are still BAD it means bad IP has no white-listed owner
                    if self.node_dict[ipAddress].bad == True:
                        logging.info(
                            "\n\"ALARM CONFIRMATION! the detected illegal IP {0} in country {1} is indeed a BAD guy.\"".format(
                                ipAddress, self.node_dict[ipAddress].country_iso))
                # else if not yet BAD: it may be an illegal OWNER -> make it BAD and add it to firewall rule
                else:
                    # owner empty?
                    if re.search("Owner Name:,", self.node_dict[ipAddress].whosip) != None:
                        logging.info("Owner is empty so we assume it is BAD!")
                        self.node_dict[ipAddress].bad = True
                        logging.info(
                            "\n\"ALARM! detected illegal owner {0} with IP {1} in country {2}\"".format("", ipAddress,
                                                                                                        self.node_dict[
                                                                                                            ipAddress].country_iso))
                    # otherwise check black list of owners
                    else:
                        for badOwner in configuration.BlackListOwner:
                            # black-listed owner?
                            if re.search("".join(["Owner Name: ", badOwner]), self.node_dict[ipAddress].whosip,
                                         re.IGNORECASE) != None:
                                reallyBad = True
                                # got black-listed owner string but - just to be 100% sure - we check that owner does NOT contain string in white-list
                                for goodOwner in configuration.WhiteListOwner:
                                    if re.search("".join(["Owner Name: ", goodOwner]), self.node_dict[ipAddress].whosip,
                                                 re.IGNORECASE) != None:
                                        # got white-listed owner string, although we had black-listed owner string
                                        logging.info(
                                            "What? got good owner string {0}, although we had bad owner string {1}. Just to be sure we leave it as GOOD!".format(
                                                goodOwner, badOwner))
                                        reallyBad = False
                                        break
                                # owner in black-list and NOT in white-list
                                if reallyBad:
                                    self.node_dict[ipAddress].bad = True
                                    logging.info(
                                        "\n\"ALARM! detected illegal owner {0} with IP {1} in country {2}\"".format(
                                            badOwner, ipAddress, self.node_dict[ipAddress].country_iso))
                                    break

                # handle BAD host as it corresponds
                if self.node_dict[ipAddress].bad == True:
                    logging.info("\n\"Processing bad IP = {0} \"".format(ipAddress))
                    # add bad IP to bad connection killer
                    self.badConnectionKillerObject.putIPToKill(ipAddress)
                    # add rule to Firewall?
                    if configuration.ADD_FIREWALL_RULE_BLOCK_BAD_IP:
                        # are we running as root?
                        if os.geteuid() == 0:
                            if configuration.ASK_BEFORE_ADDING_RULE:
                                node_infos = "".join([str(self.node_dict[ipAddress].host), "\n", \
                                                      str(self.node_dict[ipAddress].region), "\n", \
                                                      str(self.node_dict[ipAddress].city)])
                                question = Question(ipAddress, node_infos)
                                self.__mutex_question.acquire()
                                try:
                                    self.__questionListComplete.append(question)
                                except Exception as e:
                                    logging.exception("Could not append question. Exception: " + str(e))
                                finally:
                                    self.__mutex_question.release()
                            else:
                                response_src_temp = "".join([str(self.node_dict[ipAddress].country_iso), ",",
                                                             str(self.node_dict[ipAddress].city), ",",
                                                             str(self.node_dict[ipAddress].whosip).replace("'", "")])
                                # and now remove all spaces
                                # firewall does not like spaces
                                response_src_temp = response_src_temp.replace(" ", "")
                                self.firewallManagerObject.putHostToRule(ipAddress, response_src_temp)
                        else:
                            logging.error(
                                "ERROR: shall add rule to firewall to block IP " + ipAddress + " but have no root privileges!")
                    # play alarm?
                    if configuration.SOUND:
                        playsound_block_false('IPRadar2/Sounds/Alarm/salamisound-8723691-alarm-sirene-auto.mp3')

                # add/modify updated IP to GUI-List
                self.__mutex.acquire()
                self.node_dict_gui[ipAddress] = self.node_dict[ipAddress]
                self.__mutex.release()

            # set flag to update GUI
            self.needUpdate = True

    # check if new processes have been killed in order to stop the connection to a BAD IP
    def checkKilledConnections(self):
        killed_ip_dict = self.badConnectionKillerObject.getKilledIPs()
        if killed_ip_dict:
            # loop dict of killed connections
            for killed_ip, killed_process in killed_ip_dict.items():
                # mark node as killed (if available in node dict)
                if killed_ip in self.node_dict:
                    self.node_dict[killed_ip].killed = True
                    self.node_dict[killed_ip].killed_process = killed_process
                    # add/modify updated IP to GUI-List
                    self.__mutex.acquire()
                    self.node_dict_gui[killed_ip] = self.node_dict[killed_ip]
                    self.__mutex.release()
                # loop all nodes
                for ip in self.node_dict:
                    if killed_ip in self.node_dict[ip].comm_partner_list:
                        self.node_dict[ip].comm_partner_list_killed.append(killed_ip)
                        self.node_dict[ip].comm_partner_list.remove(killed_ip)
                        logging.info("".join(["Killed connection ", ip, " to ", killed_ip]))
                        # add/modify updated IP to GUI-List
                        self.__mutex.acquire()
                        self.node_dict_gui[ip] = self.node_dict[ip]
                        self.__mutex.release()
            self.needUpdate = True

    # check current active connections
    def checkActiveConnections(self):
        oldNrOfConnections = len(self.connected_ip_list)
        connected_ip_list_temp = self.badConnectionKillerObject.getConnectedIPs()
        # need deepcopy so we can remove unknown IPs later
        connected_ip_list_local = deepcopy(connected_ip_list_temp)
        if connected_ip_list_local:
            # first clear all connection flags which don't exist anymore
            for oldConnectedIP in self.connected_ip_list:
                if oldConnectedIP not in connected_ip_list_local:
                    # change from True to False
                    self.node_dict[oldConnectedIP].conn_established = False
            # loop list of active connections and set flag to True in node_dict
            for connected_ip in connected_ip_list_local:
                # need check in case we detect a connection of an IP which is not yet registered
                if connected_ip in self.node_dict:
                    self.node_dict[connected_ip].conn_established = True
                else:
                    # we make sure only known IPs are kept in the list
                    connected_ip_list_temp.remove(connected_ip)
            # cross-check to detect changes and inform GUI
            for ip in self.connected_ip_list:
                if ip not in connected_ip_list_temp:
                    # add/modify updated IP to GUI-List
                    # may be connection of IP whic is not (yet) registered
                    if ip in self.node_dict:
                        self.__mutex.acquire()
                        self.node_dict_gui[ip] = self.node_dict[ip]
                        self.__mutex.release()
            for ip in connected_ip_list_temp:
                if ip not in self.connected_ip_list:
                    # add/modify updated IP to GUI-List
                    # may be connection of IP whic is not (yet) registered
                    if ip in self.node_dict:
                        self.__mutex.acquire()
                        self.node_dict_gui[ip] = self.node_dict[ip]
                        self.__mutex.release()
            # update list of connected IPs
            self.connected_ip_list = connected_ip_list_temp
        else:
            # clear flags, reset list and also local handling
            # TODO: check if we need this statement.
            if self.connected_ip_list:
                # NOTE: getConnectedIPs() returns constantly empty list
                # so we need to check if there are really zero connections by checking nr. of connections
                if self.badConnectionKillerObject.getNumberOfConnections() == 0:
                    for oldConnectedIP in self.connected_ip_list:
                        # for some reason we need this check.
                        # TODO: how is it possible that the oldConnectedIP is NOT in the node_dict?
                        # we checked before and we copied from connected_ip_list_temp only IPs that exist in node_dict..
                        if oldConnectedIP in self.node_dict:
                            self.node_dict[oldConnectedIP].conn_established = False
                    # for some reason we need this check
                    # TODO: same as above..
                    if self.local in self.node_dict:
                        # clear also local IP
                        self.node_dict[self.local].conn_established = False
                    # now clear list
                    self.connected_ip_list = []
                else:
                    # TODO: correct this behavior: if getConnectedIPs() returns permanently empty list
                    logging.error("Error: nr. of connections = " + str(
                        self.badConnectionKillerObject.getNumberOfConnections()) + " but returned list is empty!")
        # need update?
        # for now we only update when previous nr. of connections differs to current nr. of connections
        # TODO: cover also the case where changes in connections result in the same number of connections
        if oldNrOfConnections != len(self.connected_ip_list):
            self.needUpdate = True

    # TODO: socket.gethostbyaddr() not working?
    #       use e.g. command avahi-resolve -a <IP> instead to obtain the computer name of local IPs?
    # NOTE: these methods may not always return the desired results,
    # especially if reverse DNS lookup is not properly configured for the IP addresses in your local network.
    def get_domain_name(self, ip_address):
        try:
            # hostname = socket.gethostbyaddr(ip_address)[0]
            hostname = socket.getfqdn(ip_address)
            return hostname
        except socket.herror:
            return ""

    # de-queued packets are processed here
    # set flag to "re-draw" map e.g. if new connection received!
    def processPacket(self, packet):
        logging.debug("processing nr. of packets = " + str(self.processedPacketsCount) + ", still in queue " + str(
            self.sizeOfProcessingQueue))
        # local copies of IPs
        source = packet.ip.src
        destination = packet.ip.dst
        src_ip_address = ipaddress.ip_address(source)
        dst_ip_address = ipaddress.ip_address(destination)
        # when we have our "local" IP address we map it to the "public" IP address:
        src_is_local = False
        dst_is_local = False
        # special IPs do NOT require get_mac_address(), putHostToPing()
        src_special_ip = False
        dst_special_ip = False
        host_src_resolved = False
        host_dst_resolved = False
        transmitting = False
        receiving = False
        # set SRC host if local
        if source.startswith(self.netlocal):
            if source == configuration.ROUTER_IP:
                host_src = "".join([source, " (router src) ", self.publicHost])  # public host for router/gateway
            elif source == self.local:
                host_src = "".join([source, " (my device src) ", self.localHost])
                transmitting = True
            else:
                host_src = "".join([source, " (local src) ", self.get_domain_name(source)])
            src_is_local = True
            host_src_resolved = True
        elif src_ip_address.is_reserved:
            host_src = "".join([source, " (reserved src IP) "])
            src_is_local = True
            host_src_resolved = True
            src_special_ip = True
        elif src_ip_address.is_unspecified:
            host_src = "".join([source, " (unspecified src IP) "])
            src_is_local = True
            host_src_resolved = True
            src_special_ip = True
        elif src_ip_address.is_loopback:
            host_src = "".join([source, " (loopback src IP) "])
            src_is_local = True
            host_src_resolved = True
            src_special_ip = True
        elif src_ip_address.is_link_local:
            host_src = "".join([source, " (link-local src IP) "])
            src_is_local = True
            host_src_resolved = True
        elif src_ip_address.is_private:
            host_src = "".join([source, " (private src IP - but not configured!) "])
            src_is_local = True
            host_src_resolved = True
            src_special_ip = True
        elif src_ip_address.is_global:
            host_src = "".join([source, " (global src IP) "])
        else:
            host_src = "".join([source, " src_host"])
        # and now set DST host if local
        if destination.startswith(self.netlocal):
            if destination == configuration.ROUTER_IP:
                host_dst = "".join([destination, " (router dst) ", self.publicHost])  # public host for router/gateway
            elif destination == self.local:
                host_dst = "".join([destination, " (my device dst) ", self.localHost])
                receiving = True
            # Subnet Broadcast (also called Direct Broadcast)?
            elif destination == self.net.broadcast_address.compressed:
                host_dst = "".join([destination, " (subnet broadcast dst IP) "])
                dst_special_ip = True
            else:
                host_dst = "".join([destination, " (local dst) ", self.get_domain_name(destination)])
            dst_is_local = True
            host_dst_resolved = True
        elif dst_ip_address.is_multicast:
            host_dst = "".join([destination, " (multicast dst IP) "])
            dst_is_local = True
            host_dst_resolved = True
            dst_special_ip = True
        elif destination == "255.255.255.255":
            host_dst = "".join([destination, " (broadcast dst IP) "])
            dst_is_local = True
            host_dst_resolved = True
            dst_special_ip = True
        elif dst_ip_address.is_loopback:
            host_dst = "".join([destination, " (loopback dst IP) "])
            dst_is_local = True
            host_dst_resolved = True
            dst_special_ip = True
        elif dst_ip_address.is_unspecified:  # TODO: check if this is possible
            host_dst = "".join([destination, " (unspecified dst IP) "])
            dst_is_local = True
            host_dst_resolved = True
            dst_special_ip = True
        elif dst_ip_address.is_link_local:  # TODO: check if this is possible
            host_dst = "".join([destination, " (link-local dst IP) "])
            dst_is_local = True
            host_dst_resolved = True
        elif dst_ip_address.is_private:
            host_dst = "".join([destination, " (private dst IP - but not configured!) "])
            dst_is_local = True
            host_dst_resolved = True
        elif dst_ip_address.is_global:
            host_dst = "".join([destination, " (global dst IP) "])
        else:
            host_dst = "".join([destination, " dst_host"])
        # nr. of TX and RX KiloBytes
        if transmitting:
            self.tx_kilo_bytes = self.tx_kilo_bytes + float(packet.length) / 1024.0
            self.tx_kilo_bytes_alarm = self.tx_kilo_bytes_alarm + float(packet.length) / 1024.0
            if self.tx_kilo_bytes_alarm > configuration.MAX_TX_KILOBYTES:
                # set to zero and start counting again...until we reach MAX_TX_KILOBYTES again
                self.tx_kilo_bytes_alarm = 0.0
                logging.info("".join(["ALARM: got more TX bytes than maximum = ", str(configuration.MAX_TX_KILOBYTES)]))
                if configuration.SOUND:
                    playsound_block_false('IPRadar2/Sounds/Alarm/salamisound-4299638-alarm-sirene-13-mal-heulen.mp3')
        elif receiving:
            self.rx_kilo_bytes = self.rx_kilo_bytes + float(packet.length) / 1024.0
        # is this a NEW connection?
        newConnection = True
        if source in self.node_dict:
            if destination in self.node_dict[source].comm_partner_list:
                newConnection = False
        if newConnection:
            # we have a NEW connection
            log_info_layer(packet)
            if configuration.SOUND and not configuration.ONLY_ALARMS_SOUND:
                if src_is_local and dst_is_local:
                    playsound_block_false('IPRadar2/Sounds/smb_kick.mp3')
                else:
                    playsound_block_false('IPRadar2/Sounds/smb_flagpole.mp3')
            # resolve geolocation for source address
            geoLocationNotResolved = True
            # check if src location already exists
            # TODO: check if this takes even more time than just calling DbIpCityResponse().
            #       That will depend on the size of the file locationsResolved.json and the nr. of locations we need to resolve in a specified time period.
            if src_is_local:
                # Note: local IP, we store it neither in self.locationsResolved nor in locationsResolved.json
                response_src = self.response_public
                geoLocationNotResolved = False
            else:
                for location in self.locationsResolved:
                    if location != "":
                        if location["ip_address"] == source:
                            response_src = DbIpCityResponse(
                                location["city"], location["country"], location["ip_address"], location["latitude"],
                                location["longitude"], location["region"])
                            geoLocationNotResolved = False
                            break
            # source already resolved?
            if geoLocationNotResolved:
                try:
                    response_src = DbIpCity.get(source, api_key='free')
                    # WORKAROUND:
                    # sometimes DbIpCity returns lat, lon = None, None
                    if response_src.latitude == None or response_src.longitude == None:
                        logging.error("Error: DbIpCity.get(source) lat, lon = None, None")
                        # we set a default lat lon
                        response_src.latitude = 0.1
                        response_src.longitude = 0.1
                    else:
                        geoLocationNotResolved = False
                except Exception as e:
                    logging.exception("processor.py.processPacket():Exception: DbIpCity.get(source) = " + str(e))
                    return
                # catch further errors
                if response_src == None:
                    return
                # convert new location to json format
                js = response_src.to_json()
                # append to file only if really resolved
                if geoLocationNotResolved == False:
                    locationsFile = open("IPRadar2/Config/locationsResolved.json", "a", encoding="utf-8")
                    locationsFile.write(js)
                    locationsFile.write("\n")
                    locationsFile.close()
                # store in memory
                js = json.loads(response_src.to_json())
                self.locationsResolved.append(js)
            # resolve geolocation for destination address
            geoLocationNotResolved = True
            # check if dst location already exists
            if dst_is_local:
                # Note: local IP, we store it neither in self.locationsResolved nor in locationsResolved.json
                response_dst = self.response_public
                geoLocationNotResolved = False
            else:
                for location in self.locationsResolved:
                    if location != "":
                        if location["ip_address"] == destination:
                            response_dst = DbIpCityResponse(
                                location["city"], location["country"], location["ip_address"], location["latitude"],
                                location["longitude"], location["region"])
                            geoLocationNotResolved = False
                            break
            # destination already resolved?
            if geoLocationNotResolved:
                try:
                    response_dst = DbIpCity.get(destination, api_key='free')
                    # WORKARDOUND:
                    # sometimes DbIpCity returns lat, lon = None, None
                    if response_dst.latitude == None or response_dst.longitude == None:
                        logging.warning("".join(
                            ["Warning: DbIpCity.get(", destination, ") lat, Lon = None. Assigning default values."]))
                        # we set a default lat lon
                        response_dst.latitude = 0.1
                        response_dst.longitude = 0.1
                    else:
                        geoLocationNotResolved = False
                except Exception as e:
                    logging.exception("processor.py.processPacket():Exception: DbIpCity.get(destination) = " + str(e))
                    return
                # catch further errors
                if response_dst == None:
                    return
                # convert new location to json format
                js = response_dst.to_json()
                # append to file only if really resolved
                if geoLocationNotResolved == False:
                    locationsFile = open("IPRadar2/Config/locationsResolved.json", "a", encoding="utf-8")
                    locationsFile.write(js)
                    locationsFile.write("\n")
                    locationsFile.close()
                # store in memory
                js = json.loads(response_dst.to_json())
                self.locationsResolved.append(js)
            # auto ping?
            if self.pingAuto:
                # we always ping new host as a source:
                if (source not in self.hostsPingRequested) and (source != self.local) and (src_special_ip == False):
                    self.hostsPingRequested.append(source)
                    logging.info("ping source IP = " + source)
                    self.pingResolverObject.putHostToPing(source)
                # we always ping new host as a destination:
                if (destination not in self.hostsPingRequested) and (destination != self.local) and (
                        dst_special_ip == False):
                    self.hostsPingRequested.append(destination)
                    logging.info("ping destination IP = " + destination)
                    self.pingResolverObject.putHostToPing(destination)
            # request/initiate host resolution (will be done delayed in a separate thread in background)
            if src_is_local == False:
                if source in self.hostsResolved:
                    host_src = self.hostsResolved[source]
                    # if an "unknown" host was added to the list then we don't flag it as resolved
                    if "(unknown)" not in host_src:
                        host_src_resolved = True
                elif source not in self.hostsResolutionRequested:  # could be currently in request
                    self.hostsResolutionRequested.append(source)
                    self.hostResolverObject.putHostToResolve(source)
                    if configuration.SOUND and not configuration.ONLY_ALARMS_SOUND:
                        playsound_block_false('IPRadar2/Sounds/smb_bump.mp3')
            if dst_is_local == False:
                if destination in self.hostsResolved:
                    host_dst = self.hostsResolved[destination]
                    # if an "unknown" host was added to the list then we don't flag it as resolved
                    if "(unknown)" not in host_dst:
                        host_dst_resolved = True
                elif destination not in self.hostsResolutionRequested:  # could be currently in request
                    self.hostsResolutionRequested.append(destination)
                    self.hostResolverObject.putHostToResolve(destination)
                    if configuration.SOUND and not configuration.ONLY_ALARMS_SOUND:
                        playsound_block_false('IPRadar2/Sounds/smb_bump.mp3')
            # MAC address
            # getmac page: https://github.com/GhostofGoes/getmac
            # "Remote hosts" refer to hosts in your local layer 2 network, also commonly referred to as a "broadcast domain", "LAN", or "VLAN".
            # As far as I know, there is no reliable method to get a MAC address for a remote host "external" to the LAN.
            if (src_is_local == True) and (src_special_ip == False):
                if source == configuration.ROUTER_IP:
                    mac_src = self.mac_router
                elif source == self.local:
                    mac_src = self.mac_device
                else:
                    mac_src = get_mac_address(ip=source)
            else:
                mac_src = ""
            if (dst_is_local == True) and (dst_special_ip == False):
                if destination == configuration.ROUTER_IP:
                    mac_dst = self.mac_router
                elif destination == self.local:
                    mac_dst = self.mac_device
                else:
                    mac_dst = get_mac_address(ip=destination)
            else:
                mac_dst = ""
            # create nodes
            # cases:      src         dst         (exist)
            # 1.a            x            x
            # 1.b            x
            # 2.a                         x
            # 2.b
            ################
            case = ""
            if source in self.node_dict:
                # add destination in comm_partner_list of source
                self.node_dict[source].comm_partner_list.append(destination)
                ####################
                if destination not in self.node_dict:
                    # add destination in node_dict (1.b)
                    case = "1b"
                    dest_node = NodeDataClass(self.currentNodeNumber, destination, mac_dst, response_dst.latitude,
                                              response_dst.longitude, response_dst.latitude, response_dst.longitude, 1,
                                              response_dst.country,
                                              pycountry.countries.get(alpha_2=response_dst.country),
                                              response_dst.region, response_dst.city, host_dst, True, "",
                                              host_dst_resolved, ping=False, bad=False, killed=False, killed_process="",
                                              local=dst_is_local, conn_established=False,
                                              tx=0, rx=0, tx_kB=0, rx_kB=0, date=strftime("%Y.%m.%d", gmtime()),
                                              time=strftime("%H:%M:%S", gmtime()), comm_partner_list=[],
                                              comm_partner_list_killed=[])
                    self.node_dict[
                        destination] = dest_node  # new value in dict with key destination (its like an "append")
                    self.currentNodeNumber = self.currentNodeNumber + 1
                else:
                    case = "1a"
            else:
                # add source in node_dict
                source_node = NodeDataClass(self.currentNodeNumber, source, mac_src, response_src.latitude,
                                            response_src.longitude, response_src.latitude, response_src.longitude, 1,
                                            response_src.country, pycountry.countries.get(alpha_2=response_src.country),
                                            response_src.region, response_src.city, host_src, True, "",
                                            host_src_resolved, ping=False, bad=False, killed=False, killed_process="",
                                            local=src_is_local, conn_established=False,
                                            tx=0, rx=0, tx_kB=0, rx_kB=0, date=strftime("%Y.%m.%d", gmtime()),
                                            time=strftime("%H:%M:%S", gmtime()), comm_partner_list=[destination],
                                            comm_partner_list_killed=[])
                self.node_dict[source] = source_node  # new value in dict with key source (its like an "append")
                self.currentNodeNumber = self.currentNodeNumber + 1
                # no source, check if destination exists
                if destination not in self.node_dict:
                    # add destination in node_dict (2.b)
                    case = "2b"
                    dest_node = NodeDataClass(self.currentNodeNumber, destination, mac_dst, response_dst.latitude,
                                              response_dst.longitude, response_dst.latitude, response_dst.longitude, 1,
                                              response_dst.country,
                                              pycountry.countries.get(alpha_2=response_dst.country),
                                              response_dst.region, response_dst.city, host_dst, True, "",
                                              host_dst_resolved, ping=False, bad=False, killed=False, killed_process="",
                                              local=dst_is_local, conn_established=False,
                                              tx=0, rx=0, tx_kB=0, rx_kB=0, date=strftime("%Y.%m.%d", gmtime()),
                                              time=strftime("%H:%M:%S", gmtime()), comm_partner_list=[],
                                              comm_partner_list_killed=[])
                    self.node_dict[
                        destination] = dest_node  # new value in dict with key destination (its like an "append")
                    self.currentNodeNumber = self.currentNodeNumber + 1
                else:
                    case = "2a"
            ########################
            # update module variable location_dict (src)
            latlonsrc = "".join([str(self.node_dict[source].lat), ",", str(self.node_dict[source].lon)])
            if latlonsrc in self.location_dict:
                if case == "2a" or case == "2b":
                    # increment count
                    self.location_dict[latlonsrc] = self.location_dict[latlonsrc] + 1  # updates value
                    # update also  the source position in node_dict
                    self.node_dict[source].position = self.location_dict[latlonsrc]
                    # and update the drawing position
                    # GeoLocationPhi = math.radians(360.0/self.node_dict[source].position)
                    GeoLocationPhi = math.radians(6.28 * 360.0 / self.node_dict[source].position)
                    # set delta to CIRCLE in geo-location
                    latDelta = configuration.GeoLocationRadius * math.cos(GeoLocationPhi)
                    lonDelta = configuration.GeoLocationRadius * math.sin(GeoLocationPhi)
                    self.node_dict[source].lat_plot = self.node_dict[source].lat + latDelta
                    self.node_dict[source].lon_plot = self.node_dict[source].lon + lonDelta
            else:  # it must be case 2a or 2b
                # add NEW location
                self.location_dict[latlonsrc] = 1  # new value 1 in dict with key latlonsrc (its like an "append")
                # NOTE: self.node_dict[source].position already set to 1 by default
            # update module variable location_dict (dst)
            latlondst = "".join([str(self.node_dict[destination].lat), ",", str(self.node_dict[destination].lon)])
            if latlondst in self.location_dict:
                if case == "1b" or case == "2b":
                    # increment count
                    self.location_dict[latlondst] = self.location_dict[latlondst] + 1  # updates value
                    # update also  the source position in node_dict
                    self.node_dict[destination].position = self.location_dict[latlondst]
                    # and update the drawing position
                    # GeoLocationPhi = math.radians(360.0/self.node_dict[destination].position)
                    GeoLocationPhi = math.radians(6.28 * 360.0 / self.node_dict[destination].position)
                    # set delta to CIRCLE in geo-location
                    latDelta = configuration.GeoLocationRadius * math.cos(GeoLocationPhi)
                    lonDelta = configuration.GeoLocationRadius * math.sin(GeoLocationPhi)
                    self.node_dict[destination].lat_plot = self.node_dict[destination].lat + latDelta
                    self.node_dict[destination].lon_plot = self.node_dict[destination].lon + lonDelta
            else:  # it must be case 1b or 2b
                # add NEW location
                self.location_dict[latlondst] = 1  # new value (its like an "append")
                # NOTE: self.node_dict[destination].position already set to 1 by default
            # src in black list / NOT in white list?
            if configuration.USE_WHITE_LIST:
                badIP = ((response_src.country not in configuration.WhiteList) and (
                            response_src.city not in configuration.WhiteListCity)) or (
                                    response_src.city in configuration.BlackListCity)
            else:
                badIP = ((response_src.country in configuration.BlackList) and (
                            response_src.city not in configuration.WhiteListCity)) or (
                                    response_src.city in configuration.BlackListCity)
            if badIP:
                # TODO: check this workaround - why do we need to check against sanitized_ip?
                if source not in self.sanitized_ip:
                    self.node_dict[source].bad = True
                    logging.info(
                        "\n\"ALARM! detected PRESUMABLY illegal IP {0} in country {1}, city {2} but owner not yet known.\"".format(
                            source, response_src.country, response_src.city))
                    # we delay putIPToKill(), adding rule to firewall and playing sound because it may be a whilte-listed onwer and we don't yet know the owner..
            # dst in black list or NOT in white list?
            if configuration.USE_WHITE_LIST:
                badIP = ((response_dst.country not in configuration.WhiteList) and (
                            response_dst.city not in configuration.WhiteListCity)) or (
                                    response_dst.city in configuration.BlackListCity)
            else:
                badIP = ((response_dst.country in configuration.BlackList) and (
                            response_dst.city not in configuration.WhiteListCity)) or (
                                    response_dst.city in configuration.BlackListCity)
            if badIP:
                # TODO: check this workaround - why do we need to check against sanitized_ip?
                if destination not in self.sanitized_ip:
                    self.node_dict[destination].bad = True
                    logging.info(
                        "\n\"ALARM! detected PRESUMABLY illegal IP {0} in country {1}, city {2} but owner not yet known.\"".format(
                            destination, response_dst.country, response_dst.city))
                    # we delay putIPToKill(), adding rule to firewall and playing sound because it may be a whilte-listed onwer and we don't yet know the owner..
            # print geolocations in CONSOLE
            log_geolocations(response_src, response_dst, self.node_dict[source].host, self.node_dict[destination].host)
            # add new IP to GUI-List
            # eventually both, source and destination have been created or modified
            self.__mutex.acquire()
            self.node_dict_gui[source] = self.node_dict[source]
            self.node_dict_gui[destination] = self.node_dict[destination]
            self.__mutex.release()
            # plot map is handled in block outside "if newConnection"
        # end of block "if newConnection:"
        # if both IPs already exist we only update nr. of packets in next code block, outside this else..
        #######################################################
        # common block for new and existent IPs
        #######################################################
        # Local -> Extern ?
        # for now we only care about TX bytes from local - that is, is there any INFORMATION LEAKAGE ?
        # but we also log RX to show in GUI as well.
        # increment nr. of sent bytes from local in .rx of destination, so it can be shown in marker.
        rx = int(self.node_dict[destination].rx) + int(packet.length)
        self.node_dict[destination].rx = rx
        self.node_dict[destination].rx_kB = rx // 1000
        tx = int(self.node_dict[source].tx) + int(packet.length)
        self.node_dict[source].tx = tx
        self.node_dict[source].tx_kB = tx // 1000
        # update self.node_dict_gui only if data is sent to outside: Local -> Extern
        if src_is_local == True:
            self.__mutex.acquire()
            self.node_dict_gui[destination] = self.node_dict[destination]
            self.__mutex.release()
            # set flag to update plot
            self.needUpdate = True
        # end of common block for existent and new IP addresses
        #######################################################
        # plot map
        if configuration.PLOT and newConnection:
            # update flag to update map periodically
            self.needUpdate = True
        return

    def getDictOfNodes(self):
        node_dict_gui_temp = {}
        self.__mutex.acquire()
        try:
            if self.node_dict_gui:
                for key, value in self.node_dict_gui.items():
                    node_dict_gui_temp[key] = value
                # now clear local list
                self.node_dict_gui = {}
            else:
                node_dict_gui_temp = {}
        except Exception as e:
            logging.exception("Exception in processor.getDictOfNodes() = " + str(e))
            node_dict_gui_temp = {}
        finally:
            self.__mutex.release()
        return node_dict_gui_temp

    # switch queues when currently used queue gets empty (was guaranteed before call)
    def switchQueues(self):
        if self.currentCallbackQueueIsA[0] == False:
            # queue is empty, we switch:
            # self.inputPacketsCount = 0
            self.processedPacketsCount = 0
            self.currentCallbackQueueIsA[0] = True
            logging.debug("\nLog level X: switch to callback queue A")
        else:
            # queue is empty, we switch:
            # self.inputPacketsCount = 0
            self.processedPacketsCount = 0
            self.currentCallbackQueueIsA[0] = False
            logging.debug("\nLog level X: switch to callback queue B")

    def addDenyFirewallRule(self, ipAddress):
        response_src_temp = "".join(
            [str(self.node_dict[ipAddress].country_iso), ",", str(self.node_dict[ipAddress].city), ",",
             str(self.node_dict[ipAddress].whosip).replace("'", "")])
        # and now remove all spaces, firewall doesn't like spaces
        response_src_temp = response_src_temp.replace(" ", "")
        self.firewallManagerObject.putHostToRule(ipAddress, response_src_temp)

    # thread to processing packets in queue
    def processingThread(self, packetQueueA, packetQueueB, currentCallbackQueueIsA, locationsRead):
        # set processor variables
        self.packetQueueA = packetQueueA
        self.packetQueueB = packetQueueB
        # set queue-switch-flag according configuration
        if configuration.USE_DOUBLE_BUFFER == True:
            self.currentCallbackQueueIsA = currentCallbackQueueIsA
        else:
            self.currentCallbackQueueIsA = [not self.currentCallbackQueueIsA[0]]
        self.locationsRead = locationsRead
        # synch point with sniffer thread -> signal to start now!
        self.locationsRead[0] = True
        # first time we need to wait for data on queue A,
        # we continue when queue has at least one element
        if configuration.USE_DOUBLE_BUFFER == True:
            while self.packetQueueA.empty():  # default queue at startup is A
                time.sleep(0.1)  # 100ms
            # we switch queue
            # self.inputPacketsCount = 0
            self.processedPacketsCount = 0
            self.currentCallbackQueueIsA[0] = False
            logging.debug("\nLog level X: switch to callback queue B")
        # start time
        startTime = time.time()
        # main loop
        ###########
        # poll queue as fast as we can, but make small pauses to not consume too much CPU,
        # execute periodic tasks cooperatively
        while self.close_app == False:
            sleep_before_next_queue_poll = True
            if self.currentCallbackQueueIsA[0] == False:
                if self.packetQueueA.empty() == False:
                    try:
                        # NOTE: we may use get_nowait() i.o. get(block_=True,..)
                        #       packet = self.packetQueueA.get_nowait()
                        packet = self.packetQueueA.get(block=True, timeout=configuration.POLL_PACKET_QUEUE_IN_SEC)
                        if packet != None:
                            self.processedPacketsCount = self.processedPacketsCount + 1
                            logging.debug("\nmain loop(A) pkt-nr = " + str(self.processedPacketsCount))
                            self.sizeOfProcessingQueue = self.packetQueueA.qsize()
                            self.processPacket(packet)
                            sleep_before_next_queue_poll = False
                        if configuration.USE_DOUBLE_BUFFER == True:
                            if self.packetQueueA.empty() == True:
                                # switch only if the other queue is NOT empty, otherwise continue with queueA
                                if self.packetQueueB.empty() == False:
                                    self.switchQueues()
                    except Exception as e:
                        logging.exception("Exception in packet processing in Queue A: " + str(e))
            else:
                if self.packetQueueB.empty() == False:
                    try:
                        # NOTE: we may use get_nowait() i.o. get(block_=True,..)
                        #       packet = self.packetQueueB.get_nowait()
                        packet = self.packetQueueB.get(block=True, timeout=configuration.POLL_PACKET_QUEUE_IN_SEC)
                        if packet != None:
                            self.processedPacketsCount = self.processedPacketsCount + 1
                            logging.debug("\nmain loop(B) pkt-nr = " + str(self.processedPacketsCount))
                            self.sizeOfProcessingQueue = self.packetQueueB.qsize()
                            self.processPacket(packet)
                            sleep_before_next_queue_poll = False
                        if self.packetQueueB.empty() == True:
                            if configuration.USE_DOUBLE_BUFFER == True:
                                # switch only if the other queue is NOT empty, otherwise continue with queueB
                                if self.packetQueueA.empty() == False:
                                    self.switchQueues()
                    except Exception:  # as e:
                        logging.exception("Exception in packet processing in Queue B: " + str(e))
            # currentTime
            timeDiff = time.time() - startTime
            # periodic tasks
            ################
            if timeDiff > configuration.CHECK_PERIOD_IN_SEC:
                # start time
                startTime = time.time()
                logging.debug("Checking processing status..")
                self.checkForHostsPinged()
                self.checkForHostsResolution()
                self.checkKilledConnections()
                self.checkActiveConnections()
                # plot map
                if configuration.PLOT and self.needUpdate:
                    self.plotMap()
                sleep_before_next_queue_poll = False
            # we need to wait a little bit in order to not consume too much CPU
            if sleep_before_next_queue_poll:
                time.sleep(configuration.POLL_PACKET_QUEUE_IN_SEC)
        # end of processingThread()
        logging.info("leaving processingThread..")
