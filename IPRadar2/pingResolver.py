import sys
if "IPRadar2" in str(sys.argv):
    import configuration
else:
    from IPRadar2 import configuration
import logging
import queue
from threading import Lock
from copy import deepcopy
from pythonping import ping
from time import sleep
import os
import subprocess
import re



class PingResolverClass(object):
    __hostPingQueue = queue.Queue()
    __hostPingedList = []
    __mutexSolved = Lock()
    pingedHosts = [] # permanent list

    def __init__(self):
        return

    # ping host IP
    ##############
    def __pingHost(self,  hostIP):
        if os.geteuid() == 0:
            # ping as root
            try:
                response_list = ping(hostIP, timeout=configuration.PING_TIMEOUT_SEC,  size=configuration.PING_SIZE_BYTES, count=configuration.PING_COUNT)
                logging.debug(response_list)
                # when the response is "Request timed out.." then we get rtt_avg_ms = PING_TIMEOUT_SEC (in ms)
                if response_list.rtt_min < configuration.PING_TIMEOUT_SEC:
                    logging.debug("Ping to IP = " + hostIP)
                    logging.debug("rtt_min_ms = " + str(response_list.rtt_min_ms))
                    logging.debug("rtt_avg_ms = " + str(response_list.rtt_avg_ms))
                    self.__mutexSolved.acquire()
                    self.__hostPingedList.append(hostIP)
                    self.__mutexSolved.release()
                    # check if response is close to timeout and log infos in that case
                    if (configuration.PING_TIMEOUT_SEC - response_list.rtt_max) < configuration.PING_TIMEOUT_SEC*0.1:
                        logging.warning("WARNING: ping response close to max. value, rtt_max_ms = " + str(response_list.rtt_max_ms))
                else:
                    logging.info("".join(["Time out in Ping to IP = " , hostIP]))
            except Exception as e:
                logging.exception("".join(["Exception in ping: " , str(e)]))
                logging.exception("".join(["Exception in Ping to IP = " , hostIP]))
        else:
            # ping as non-root user
            try:
                # TODO: use fping where timeouts < 1 sec are possible, i.o. ping?
                #       But then we force users to install it on their system
                #       creating another dependency to tools which are not installed by default
                command = ["ping", "-c", str(configuration.PING_COUNT), "-w", str(configuration.PING_TIMEOUT_SEC), "-s", str(configuration.PING_SIZE_BYTES), hostIP]
                logging.info(command)
                out = subprocess.check_output(command)
                if out != '':
                    line = out.decode('utf-8')
                    line = line.splitlines()
                    line = line[len(line)-1]
                    pattern = r"= .*?(?= ms)"
                    stats = re.search(pattern, line).group()[2:]
                    stats = stats.split("/")
                    rtt_min_ms = stats[0]
                    rtt_max_ms = stats[1]
                    rtt_avg_ms = stats[2]
                    logging.debug("Ping to IP = " + hostIP)
                    logging.debug("rtt_min_ms = " + rtt_min_ms)
                    logging.debug("rtt_avg_ms = " + rtt_avg_ms)
                    self.__mutexSolved.acquire()
                    self.__hostPingedList.append(hostIP)
                    self.__mutexSolved.release()
                    # check if response is close to timeout and log infos in that case
                    if (configuration.PING_TIMEOUT_SEC*1000.0 - float(rtt_max_ms)) < configuration.PING_TIMEOUT_SEC*100.0:
                        logging.warning("WARNING: ping response close to max. value, rtt_max_ms = " + rtt_max_ms)
                else:
                    logging.error("".join(["Error: could not execute ping correctly on host = " , hostIP]))
            except Exception as e:  # avoid catching exceptions like SystemExit, KeyboardInterrupt, etc.
                # NOTE: don't log the exception to keep output clean,
                #       we get an exception e.g. when the pinged host does not answer
                #       logging.exception("Exception in ping: " + str(e))
                logging.warning("".join(["Exception in Ping to IP = " , hostIP]))

    # process hosts in queue
    ########################
    def processingThread(self):
        while True:
            # this call does NOT block
            if not self.__hostPingQueue.empty():
                pingHost = self.__hostPingQueue.get_nowait()
                if  pingHost != None:
                    self.__pingHost(pingHost)
            if self.__hostPingQueue.empty():
                sleep(configuration.CHECK_PERIOD_IN_SEC)

    # get pinged hosts
    ##################
    def getPingedHosts(self):
        self.__mutexSolved.acquire()
        try:
            if self.__hostPingedList:
                pingedHostsTemp = deepcopy(self.__hostPingedList)
                # emtpy/clear the list with resolved hosts, they were passed already
                self.__hostPingedList = []
            else:
                pingedHostsTemp = []
        except Exception as e:
            logging.exception("Exception in getPingedHosts = " + str(e))
            pingedHostsTemp = []
        finally:
            self.__mutexSolved.release()
        return pingedHostsTemp

    # put IP to ping
    ################
    def putHostToPing(self,  ip):
        # store in permanent list
        self.pingedHosts.append(ip)
        # add host to ping queue:
        self.__hostPingQueue.put(ip)
