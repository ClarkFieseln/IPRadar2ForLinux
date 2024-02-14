import sys
if "IPRadar2" in str(sys.argv):
    import configuration
else:
    from IPRadar2 import configuration
import queue
from threading import Lock
from copy import deepcopy
from time import sleep
import time
import subprocess
import logging



class FirewallManagerClass(object):
    __hostRuleQueue = queue.Queue()
    __mutexSolved = Lock()
    ruledHostName = {}
    ruledHosts = [] # permanent list

    def __init__(self):
        return

    # add rule in ufw Firewall to block host IP
    ###########################################
    def __ruleHost(self,  hostIP):
        self.__mutexSolved.acquire()
        try:
            currentTime = time.strftime("%Y_%m_%d_%H_%M_%S", time.gmtime())
            # 1) avoid duplicated entries by first trying:
            logging.info("".join(["Check if firewall rule exists before adding it. IP = " , hostIP]))
            command = "".join(["ufw status | grep \"" , configuration.RULE_NAME_STR , "\" | grep \"" , hostIP , "\""])
            p1 = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
            if p1.returncode == 0:
                p1.terminate()
                p1.kill()
                logging.info("Firewall rule exists already, nothing to do.")
            else:
                p1.terminate()
                p1.kill()
                logging.debug("We can add inbound firewall rule!")
                #################################################
                # 2) add rule to block inbound traffic from BAD IP:
                command = "".join(["ufw deny in comment \"IPRadar2-Block-" , currentTime , ": in from " , self.ruledHostName[hostIP] , "\" from " , hostIP])
                p2 = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
                p2.wait()
                if p2.returncode == 0:
                    p2.terminate()
                    p2.kill()
                    # 3) add rule to block outbound traffic from BAD IP:
                    logging.debug("We can add outbound firewall rule!")
                    command = "".join(["ufw deny out comment \"IPRadar2-Block-" , currentTime , ": out to " , self.ruledHostName[hostIP] , "\" to " , hostIP])
                    p3 = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
                    p3.wait()
                    if p3.returncode == 0:
                        logging.info("Added inbound and outbound rules successfully!")
                    else:
                        logging.error("Error: could not add out rule for IP " + hostIP)
                    p3.terminate()
                    p3.kill()
                else:
                    p2.terminate()
                    p2.kill()
                    logging.error("Error: could not add in rule for IP " + hostIP)
        except Exception as e:
            logging.exception("Exception in __ruleHost() = " + str(e))
        finally:
            self.__mutexSolved.release()

    # process hosts in queue
    ########################
    def processingThread(self):
        while True:
            if not self.__hostRuleQueue.empty():
                ruleHost = self.__hostRuleQueue.get_nowait()
                # add rule
                if  ruleHost != None:
                    self.__ruleHost(ruleHost)
            if self.__hostRuleQueue.empty():
                sleep(configuration.CHECK_PERIOD_IN_SEC)

    # get ruled hosts
    #################
    def getRuledHosts(self):
        self.__mutexSolved.acquire()
        try:
            if self.__hostRuledList:
                ruledHostsTemp = deepcopy(self.__hostRuledList)
                self.__hostRuledList = []
            else:
                ruledHostsTemp = []
        except Exception as e:
            logging.exception("Exception in getRuledHosts() = " + str(e))
            ruledHostsTemp = []
        finally:
            self.__mutexSolved.release()
        return ruledHostsTemp

    # put IP to rule (block in ufw Firewall by adding a new rule for in and out traffic from or to this IP)
    def putHostToRule(self,  ip, name):
        # store in permanent list
        self.ruledHosts.append(ip) 
        # store name in dict
        self.ruledHostName[ip] = name
        # add host to rule queue:
        self.__hostRuleQueue.put(ip)
