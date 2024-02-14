import sys
if "IPRadar2" in str(sys.argv):
    import configuration
    from helper_functions import playsound_block_false
else:
    from IPRadar2 import configuration
    from IPRadar2.helper_functions import playsound_block_false
import logging
import queue
from threading import Lock
import subprocess
from copy import deepcopy
from time import sleep
import socket



class HostResolverClass(object):
    __hostRequestResolutionQueue = queue.Queue()
    __hostResolvedList = []
    __hostsNotResolved = []
    __mutexSolved = Lock()
    # counters
    hostsRequested = 0
    hostsResolved = 0
    hostsFailed = 0
    countersLock = Lock()

    def get_domain_name(self, ip_address):
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            return hostname
        except socket.herror:
            return "(unknown)"

    def __init__(self):
        return

    def getHostsFailedPast(self):
        return len(self.__hostsNotResolved) - 1

    # use command-line tool to resolve host
    # TODO: improvement:
    # store all individual fields of whois in separate fields in node so we can use them directly and avoid parsing.
    # e.g. see checkForHostsResolution() when checking if owner is in configuration.WhiteListOwner
    ################################################################################################################
    def whosip(self,  hostIP):
        whosip_response = "Owner Name: __unknown__"
        try:
            command = "".join(["whois " , hostIP , " | grep -e OrgName: -e org-name: -e org: -e descr: -e role:"])
            logging.info(command)
            p1 = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
            out, err = p1.communicate()
            if p1.returncode == 0:
                p1.terminate()
                p1.kill()
                line = out.decode('utf-8')
                line = line.splitlines()[0]
                org_name = line[line.find(':')+1:]
                org_name = org_name.lstrip()
                org_name = org_name.replace(' ', '_')
                org_name = org_name.replace(',', '_')
                org_name = org_name.replace('\n', '_')
                whosip_response = "".join(["Owner Name: " , org_name])
            else:
                p1.terminate()
                p1.kill()
                logging.error("Error: could not execute whois correctly to find host information. Host = " + hostIP)
        except Exception as e: # avoid catching exceptions like SystemExit, KeyboardInterrupt, etc.
            logging.exception("whosip(): Exception: " + str(e))
        host = self.get_domain_name(hostIP)
        # build dictionary element
        dict_elem_host = {"ip" : hostIP, "host" : "".join([hostIP , " " , host]), "whosip" : whosip_response}
        return dict_elem_host

    # de-queued hosts are processed here
    ####################################
    def __processHost(self,  hostIP):
        self.__mutexSolved.acquire()
        try:
            dict_elem_host = self.whosip(hostIP)
            logging.info("".join(["resolved host as dict: " , dict_elem_host["ip"]]))
            self.__hostResolvedList.append(dict_elem_host)
            self.countersLock.acquire()
            self.hostsResolved = self.hostsResolved + 1
            self.countersLock.release()
            if configuration.SOUND and not configuration.ONLY_ALARMS_SOUND:
                playsound_block_false('IPRadar2/Sounds/smb_jump-small.mp3')
        except Exception as e: # avoid catching exceptions like SystemExit, KeyboardInterrupt, etc.
            logging.exception("__processHost(): Exception while trying to resolve IP " +  hostIP)
            logging.exception("__processHost(): Exception: " + str(e))
            # just in case we empty the queue, could be corrupted,
            # we assume that any previous element has been consumed up to now.
            self.__hostResolvedList = []
            # append unresolved host to list
            if hostIP not in self.__hostsNotResolved:
                self.__hostsNotResolved.append(hostIP)
                self.countersLock.acquire()
                self.hostsFailed = self.hostsFailed + 1
                self.countersLock.release()
            if configuration.SOUND and not configuration.ONLY_ALARMS_SOUND:
                playsound_block_false('IPRadar2/Sounds/smb_mariodie.mp3')
        finally:
            self.__mutexSolved.release()

    # process hosts in queue
    ########################
    def processingThread(self):
        while True:
            if not self.__hostRequestResolutionQueue.empty():
                host = self.__hostRequestResolutionQueue.get_nowait()
                if  host != None:
                    # resolve host name
                    self.__processHost(host)
            if self.__hostRequestResolutionQueue.empty():
                sleep(configuration.CHECK_PERIOD_IN_SEC)

    # get resolved hosts
    ####################
    def getResolvedHosts(self):
        self.__mutexSolved.acquire()
        try:
            if self.__hostResolvedList:
                resolvedHostsTemp = deepcopy(self.__hostResolvedList)
                # emtpy/clear the list with resolved hosts, they were passed already
                self.__hostResolvedList = []
            else:
                resolvedHostsTemp = []
        except Exception as e:
            logging.exception("Exception in getResolvedHosts = " + str(e))
            resolvedHostsTemp = []
        finally:
            self.__mutexSolved.release()
        return resolvedHostsTemp

    # put host to resolve
    #####################
    def putHostToResolve(self,  host):
        # try to resolve ONLY ONCE
        if host not in self.__hostsNotResolved:
            self.__hostRequestResolutionQueue.put(host)
            self.countersLock.acquire()
            self.hostsRequested = self.hostsRequested + 1
            self.countersLock.release()

    def getNumberOfHostsRequested(self):
        self.countersLock.acquire()
        tempVal = self.hostsRequested
        self.countersLock.release()
        return tempVal

    def getNumberOfHostsSolved(self):
        self.countersLock.acquire()
        tempVal = self.hostsResolved
        self.countersLock.release()
        return tempVal

    def getNumberOfHostsFailed(self):
        self.countersLock.acquire()
        tempVal = self.hostsFailed
        self.countersLock.release()
        return tempVal
    
