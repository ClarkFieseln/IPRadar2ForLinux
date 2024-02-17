import sys
if "IPRadar2" in str(sys.argv):
    import configuration
    from helper_functions import find_2nd
    import processor
else:
    from IPRadar2 import configuration
    from IPRadar2.helper_functions import find_2nd
    from IPRadar2 import processor
import pyshark
from time import sleep
import threading
import queue
import subprocess
from pathlib import Path
import logging
import asyncio



class pysharkSnifferClass:
    threadForSniffing = 0 
    threadForPacketProcessing = 1
    capture = 0
    fname = ""
    interface = configuration.INTERFACE
    threadsStarted = False
    inputPacketsCount = 0
    tsharkInterfaces = {}
    # double queue for processing
    # TODO: improvement: do we need double buffering? with one buffer it works well.
    # callback -> queueA/B 
    # queueB/A -> process 
    #########################
    # NOTE:
    # Mutable objects which can be passed by reference:
    # list, dict, set, byte array
    # Immutable objects: Immutable objects don’t allow modification after creation
    # bool, int, float, complex, string, tuple, frozen set [note: immutable version of set], bytes
    #########################
    packetQueueA = queue.Queue()
    packetQueueB = queue.Queue()
    currentCallbackQueueIsA = [True]
    locationsRead = [False] # we use a "list" instead of a bool so we have a "mutable" variable which we can pass by reference!
    processorObject = processor.ProcessorClass()

    def __init__(self):
        logging.info("pysharkSniffer initialized")
        # list available interfaces
        currAbsPath = Path().absolute()
        currAbsPath = str(currAbsPath)
        currAbsPath = currAbsPath.replace("\\", "/")
        logging.info("".join(["Current directory: " , currAbsPath]))
        cmdListInterfaces = "".join([configuration.CAPTURE_TOOL , " -D"])
        logging.info("Capture interfaces:")
        p1 = subprocess.Popen(cmdListInterfaces, shell=True, stdout=subprocess.PIPE)
        out, err = p1.communicate()
        if p1.returncode == 0:
            p1.terminate()
            p1.kill()
            out = out.splitlines()
            interfaceNr = 1
            for interface in out:
                interface = str(interface)
                # need to change \\ into \
                interface = interface.replace("\\\\",  "\\")
                interfaceStr = interface[interface.find(".")+2:find_2nd(interface, " ")]
                self.tsharkInterfaces[interfaceStr] = interfaceStr
                logging.info("Interface {} = {}".format(interfaceNr, interfaceStr))
                interfaceNr = interfaceNr + 1
        else:
            p1.terminate()
            p1.kill()
            logging.error("Error: could not get interfaces using " + configuration.CAPTURE_TOOL)

    def getInterfaces(self):
        return self.tsharkInterfaces

    def toggleHeatmap(self):
        if configuration.HEATMAP == True:
            configuration.HEATMAP = False
            status = "OFF"
        else:
            configuration.HEATMAP = True
            status = "ON"
        # update map
        self.processorObject.updateMap()
        return status

    def toggleShowNodes(self):
        configuration.SHOW_NODES = not configuration.SHOW_NODES
        self.processorObject.updateMap()

    def toggleShowLabels(self):
        configuration.SHOW_LABELS = not configuration.SHOW_LABELS
        self.processorObject.updateMap()

    def toggleShowConnections(self):
        configuration.SHOW_CONNECTIONS = not configuration.SHOW_CONNECTIONS
        self.processorObject.updateMap()

    def toggleShowConnectionsActive(self):
        configuration.SHOW_CONNECTIONS_ACTIVE = not configuration.SHOW_CONNECTIONS_ACTIVE
        self.processorObject.updateMap()

    def toggleShowInfo(self):
        configuration.SHOW_INFO = not configuration.SHOW_INFO
        self.processorObject.updateMap()

    def toggleShowGoodHosts(self):
        configuration.SHOW_HOST_GOOD = not configuration.SHOW_HOST_GOOD
        self.processorObject.updateMap()

    def toggleShowUnknownHosts(self):
        configuration.SHOW_HOST_UNKNOWN = not configuration.SHOW_HOST_UNKNOWN
        self.processorObject.updateMap()

    def toggleShowBadHosts(self):
        configuration.SHOW_HOST_BAD = not configuration.SHOW_HOST_BAD
        self.processorObject.updateMap()

    def toggleShowKilledHosts(self):
        configuration.SHOW_HOST_KILLED = not configuration.SHOW_HOST_KILLED
        self.processorObject.updateMap()

    def toggleShowActiveHosts(self):
        configuration.SHOW_HOST_ACTIVE = not configuration.SHOW_HOST_ACTIVE
        self.processorObject.updateMap()

    def toggleShowPingedNegHosts(self):
        configuration.SHOW_HOST_PING = not configuration.SHOW_HOST_PING
        self.processorObject.updateMap()

    def toggleShowGoodConnections(self):
        configuration.SHOW_CONNECTION_GOOD = not configuration.SHOW_CONNECTION_GOOD
        self.processorObject.updateMap()

    def toggleShowUnknownConnections(self):
        configuration.SHOW_CONNECTION_UNKNOWN = not configuration.SHOW_CONNECTION_UNKNOWN
        self.processorObject.updateMap()

    def toggleShowBadConnections(self):
        configuration.SHOW_CONNECTION_BAD = not configuration.SHOW_CONNECTION_BAD
        self.processorObject.updateMap()

    def toggleShowKilledConnections(self):
        configuration.SHOW_CONNECTION_KILLED = not configuration.SHOW_CONNECTION_KILLED
        self.processorObject.updateMap()

    def setPlot(self,  set):
        configuration.PLOT = set
        self.processorObject.updateMap()

    def setSound(self,  set):
        configuration.SOUND = set

    def setAlarmsOnly(self, set):
        configuration.ONLY_ALARMS_SOUND = set

    def setBlockBadInFirewall(self, set):
        configuration.ADD_FIREWALL_RULE_BLOCK_BAD_IP = set

    def getNumberOfConnections(self):
        return self.processorObject.getNumberOfConnections()

    def getNumberOfNodes(self):
        return self.processorObject.getNumberOfNodes()

    def getNumberOfBadNodes(self):
        return self.processorObject.getNumberOfBadNodes()

    def getDictOfNodes(self):
        return self.processorObject.getDictOfNodes()

    def getNumberOfKilledNodes(self):
        return self.processorObject.getNumberOfKilledNodes()

    def getListOfKilledNodes(self):
        return self.processorObject.getListOfKilledNodes()

    def getListOfFirewallQuestions(self):
        return self.processorObject.getListOfFirewallQuestions()

    def addDenyFirewallRule(self, ip):
        return self.processorObject.addDenyFirewallRule(ip)

    def getNumberOfInPackets(self):
        return self.inputPacketsCount

    def getNumberOfProcessedPackets(self):
        return self.processorObject.getNumberOfProcessedPackets()

    def getNumberOfQueuedPackets(self):
        return self.processorObject.getNumberOfQueuedPackets()

    def getNumberOfTxKiloBytes(self):
        return self.processorObject.getNumberOfTxKiloBytes()

    def getNumberOfRxKiloBytes(self):
        return self.processorObject.getNumberOfRxKiloBytes()

    def getNumberOfHostsRequested(self):
        return self.processorObject.getNumberOfHostsRequested()

    def getNumberOfHostsSolved(self):
        return self.processorObject.getNumberOfHostsSolved()

    def getNumberOfHostsFailed(self):
        return self.processorObject.getNumberOfHostsFailed()

    def getHostsFailedPast(self):
        return self.processorObject.getHostsFailedPast()

    def getHostsResolvedPast(self):
        return self.processorObject.getHostsResolvedPast()

    # setting to kill connections to bad IPs automatically
    def killIPs(self):
        self.processorObject.killIPs()

    # setting to kill no IPs
    def killNone(self):
        self.processorObject.killNone()

    # setting to kill connections to all known IPs automatically
    def killAll(self):
        self.processorObject.killAll()

    # COMMAND to kill connections to BAD IPs (executed once)
    def killIPsNow(self):
        self.processorObject.killIPsNow()

    # COMMAND to kill connections to all active IPs (executed once)
    def killAllNow(self):
        self.processorObject.killAllNow()

    # COMMAND to kill connections to specified IP (executed once)
    def killIP(self,  ip):
        self.processorObject.killIP(ip)

    def pingAll(self):
        if self.processorObject != None:
            self.processorObject.pingAll()

    def pingRandom(self):
        if self.processorObject != None:
            self.processorObject.pingRandom()

    def pingRandom2(self):
        if self.processorObject != None:
            self.processorObject.pingRandom2()

    def pingIP(self,  ip):
        if self.processorObject != None:
            self.processorObject.pingIP(ip)

    def pingAuto(self,  set):
        if self.processorObject != None:
            if set:
                self.processorObject.pingAutoOn()
            else:
                self.processorObject.pingAutoOff()

    def updateShowNotShowOwners(self, listOwnersToShow, listOwnersToHide):
        self.processorObject.updateShowNotShowOwners(listOwnersToShow, listOwnersToHide)

    def updateShowNotShowHost(self, ip, show):
        self.processorObject.updateShowNotShowHost(ip, show)

    def clearSelectedIp(self):
        self.processorObject.clearSelectedIp()

    def showAllHosts(self, show):
        self.processorObject.showAllHosts(show)

    def set_netmask(self):
        self.processorObject.set_netmask()

    def close(self):
        self.processorObject.close()

    def sniff(self,  interface, fname=""):
        self.fname = fname
        self.interface = interface
        # create threads
        # NOTE: order of creation based on dependencies!
        if self.threadsStarted == False:
            # initialize explicitly, so we know the point where all processing threads are started
            self.processorObject.start()
            # we create packet processing thread (threadForSniffing needs it)
            # call without parenthesis, therefore we will have a "non-blocking" thread
            self.threadForPacketProcessing = threading.Thread(name="packetProcessingThread", target=self.processorObject.processingThread,  args=(self.packetQueueA, self.packetQueueB, self.currentCallbackQueueIsA, self.locationsRead))
            self.threadForPacketProcessing.start()
        # sniffingThread for live capture
        if self.fname == "":
            self.threadForSniffing = threading.Thread(name="sniffingThread", target=self.sniffingThread)
            self.threadForSniffing.start()
        # open a capture file offline
        else:
            # we call target=keyProcessingThread()) with parenthesis so we have a "blocking" thread - block until file is processed!
            self.threadForSniffing = threading.Thread(name="sniffingThread", target=self.sniffingThread())
            self.threadForSniffing.start()
            self.threadsStarted = True

    # if used for live-capture, this call will be blocked for ever after assigning the pyshark callback for LiveCapture sniffing
    # if used for reading file this call will not block
    def sniffingThread(self):
        # callback function to process packets
        ######################################
        def packet_callback(packet):
            # TODO: remove or adapt e.g. to extend to IPv6 and other traffic
            # with this, we only process IPv4 packets further below...
            if not "IP" in packet:
                return
            if self.currentCallbackQueueIsA[0] == True:
                self.inputPacketsCount = self.inputPacketsCount + 1
                logging.debug("\Log level X: ncallback (A), packet-in= " + str(self.inputPacketsCount))
                self.packetQueueA.put(packet)
            else:
                self.inputPacketsCount = self.inputPacketsCount + 1
                logging.debug("\Log level X: ncallback (B), packet-in = " + str(self.inputPacketsCount))
                self.packetQueueB.put(packet)
        # wait for processing thread to have read locations from .json file
        ###################################################################
        while self.locationsRead[0] == False:
            sleep(0.1) # 100ms
        # live capture or open file?
        ############################
        if self.fname == "":
            # live capture
            ##############
            logging.info("".join(["opening interface " , str(self.interface)]))
            outputfile = "".join(['./IPRadar2/Output/log_' , configuration.START_TIME , '.pcapng'])
            loop = asyncio.new_event_loop()
            # NOTE: asyncio.set_event_loop(loop) isn't necessary, it is done later in pyshark
            #
            # NOTE: help on BPF filters:
            #       https://biot.com/capstats/bpf.html
            # NOTE: help on display filters:
            #       https://wiki.wireshark.org/DisplayFilters
            # NOTE: Display filters aren't supported when capturing and saving the captured packets.
            if configuration.USE_RING_BUFFER == False:
                self.capture = pyshark.LiveCapture(eventloop=loop, interface=self.interface, output_file=outputfile, bpf_filter=configuration.BPF_FILTER)
            else:
                self.capture = pyshark.LiveRingCapture(eventloop=loop, interface=self.interface, bpf_filter=configuration.BPF_FILTER)
            # set callback to capture packets (this call will "block"!)
            ###########################################################
            logging.info("Start capturing packets using callback..")
            try:
                self.capture.apply_on_packets(packet_callback)
            except Exception as e:
                logging.exception("pysharkSniffer.sniffingThread(): Exception in call to apply_on_packets(): " + str(e))
        else:
            # open file
            ###########
            logging.info("Start reading packets from file..")
            cap = pyshark.FileCapture(self.fname)
            # process packets
            for packet in cap:
                packet_callback(packet)
            # NOTE: no need to kill thread, here we go out of it (non-blocking call). Thread will be garbage-collected.
            logging.info("Read and processed all packets from file.")
