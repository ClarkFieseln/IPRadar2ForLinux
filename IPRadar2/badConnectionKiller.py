import sys
if "IPRadar2" in str(sys.argv):
    import configuration
    from helper_functions import playsound_block_false, find_2nd
else:
    from IPRadar2 import configuration
    from IPRadar2.helper_functions import playsound_block_false, find_2nd
import queue
from threading import Lock
from copy import deepcopy
from time import sleep
import subprocess
import os
import psutil
import re
import logging



class BadConnectionKillerClass(object):
    parentPID = 9999999
    ownPID = os.getpid()
    dontKillPIDs = []  # parent and all its children
    __badIPQueue = queue.Queue()
    __ipToKillList = []  # TODO: use dict instead?
    __ipKilledList = {}  # all processes with connections to IPs in this list are periodically killed
    __ipKilledListComplete = []  # all processes with connections to IPs in this list were actually killed
    __ipConnectedList = []  # TODO: use dict instead?
    __mutex = Lock()
    __mutexActiveConn = Lock()
    # counters
    nrOfBadIPs = 0  # just len(__badIPQueue)
    countersLock = Lock()
    doKillIPs = False
    doKillAll = False
    local = "127.0.0.0"  # will be set by processor
    doCheckActiveConnections = False
    numberOfConnections = 0

    def __init__(self):
        # get PID of console child
        logging.info("badConnectionKiller: own PID = " + str(self.ownPID))
        p = psutil.Process(self.ownPID)
        self.parentPID = p.ppid()
        logging.info("parent PID = " + str(self.parentPID))
        listOfPIDs = psutil.Process(self.parentPID).children(recursive=True)
        listOfPIDs = str(listOfPIDs)
        logging.info("children of parent = " + str(listOfPIDs))
        # append PIDs (of children) that we shall NOT kill..
        while "pid=" in listOfPIDs:
            childPIDTemp = listOfPIDs[listOfPIDs.find("pid=") + 4:listOfPIDs.find(",")]
            self.dontKillPIDs.append(childPIDTemp)
            # keep final part only and continue parsing..
            listOfPIDs = listOfPIDs[listOfPIDs.find(",") + 1:]
            listOfPIDs = listOfPIDs[listOfPIDs.find("pid="):]
        # append also PID of parent
        self.dontKillPIDs.append(str(self.parentPID))
        logging.info("dontKillPIDs = " + str(self.dontKillPIDs))

    def setLocalIP(self, local):
        self.local = local

    def __killAll(self):
        try:
            logging.info("Checking connected IPs = ")
            command = "netstat -anolp 2>/dev/null | grep -v unix | grep \"" + configuration.CONN_ESTABLISHED_STR + "\" | grep \""
            command = command + self.local + "\""
            p1 = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
            out, err = p1.communicate()
            if p1.returncode == 0:
                p1.terminate()
                p1.kill()
                out = out.decode('utf-8')
                out = out.splitlines()
                # TODO: improvement
                # inside loop we may have repeated PIDs = same process holding several connections
                # now we try to kill this PID several times: once per connection
                # we may store the PIDs in a dict (without repetition) and kill only once as required.
                ######################################################################################
                for netstatLine in out:
                    line = str(netstatLine)
                    logging.debug(line)
                    # TODO: improvement
                    # find a way to get the PID of the "sub-process" so e.g. we dont shut down browser completely (?)
                    #################################################################################################
                    pid = re.split(r' +', line)
                    pid = pid[6]
                    pid = pid[:pid.rfind('/')]
                    indexi = find_2nd(line[24:], " ")
                    indexi = indexi + 24
                    IP = line[indexi:line.find(":", indexi)]
                    IP = IP.replace(" ", "")
                    p = psutil.Process(int(pid))
                    pname = p.name()
                    # don't kill processes in white list
                    if pname not in configuration.WhiteListNotKill:
                        # don't kill ourselves!
                        if pid not in self.dontKillPIDs:
                            try:
                                p.kill()
                            except:
                                logging.exception("Could not kill PID = " + str(pid))
                            if IP not in self.__ipKilledList:
                                self.__ipKilledList[IP] = pname
                            message = "Killed process " + pname + " with PID = " + pid + " connected to " + IP
                            self.__ipKilledListComplete.append(pname + " (" + IP + ")")
                            if configuration.SOUND and not configuration.ONLY_ALARMS_SOUND:
                                playsound_block_false('IPRadar2/Sounds/smb_bowserfalls.mp3')
                        else:
                            message = "We do NOT kill " + pname + " with PID = " + pid + " connected to " + IP
                        logging.info(message)
                    else:
                        message = "Did NOT kill process " + pname + " with PID = " + pid + " holding a connection with IP = " + IP + " because it is in the white-list!"
                        logging.info(message)
            else:
                p1.terminate()
                p1.kill()
                logging.error("Error: could not execute netstat correctly!")
        except Exception as e:  # avoid catching exceptions like SystemExit, KeyboardInterrupt, etc.
            logging.exception("__killAll(): Exception: " + str(e))

    # de-queued hosts are processed here
    ####################################
    def __processBadIPs(self):
        self.__mutex.acquire()
        try:
            # __ipToKillList has list of IPs to kill
            for badIP in self.__ipToKillList:
                logging.info("Checking bad IP = " + str(badIP))
                command = "netstat -anolp 2>/dev/null | grep -v unix | grep \"" + configuration.CONN_ESTABLISHED_STR + "\" | grep \""
                command = command + self.local + "\""
                command = command + " | grep \""
                command = command + badIP + "\""
                p1 = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
                out, err = p1.communicate()
                if p1.returncode == 0:
                    p1.terminate()
                    p1.kill()
                    out = out.decode('utf-8')
                    out = out.splitlines()
                    for netstatLine in out:
                        line = str(netstatLine)
                        logging.debug(line)
                        # TODO: improvement
                        # find a way to get the PID of the "sub-process" so e.g. we dont shut down browser completely
                        #############################################################################################
                        pid = re.split(r' +', line)
                        pid = pid[6]
                        pid = pid[:pid.rfind('/')]
                        p = psutil.Process(int(pid))
                        pname = p.name()
                        # don't kill processes in white list
                        if pname not in configuration.WhiteListNotKill:
                            try:
                                p.kill()
                                if badIP not in self.__ipKilledList:
                                    self.__ipKilledList[badIP] = pname
                                message = "Killed process " + pname + " with PID = " + pid + " holding a connection with bad IP = " + badIP
                                logging.info(message)
                                self.__ipKilledListComplete.append(pname + " (" + badIP + ")")
                                if configuration.SOUND and not configuration.ONLY_ALARMS_SOUND:
                                    playsound_block_false('IPRadar2/Sounds/smb_bowserfalls.mp3')
                            except:
                                logging.exception("Could NOT kill PID = " + str(pid))
                        else:
                            message = "Did NOT kill process " + pname + " with PID = " + pid + " holding a connection with bad IP = " + badIP + " because it is in the white-list!"
                            logging.info(message)
                else:
                    p1.terminate()
                    p1.kill()
                    logging.error("Error: could not execute netstat correctly while trying to kill Bad IP = " + badIP)
                # maybe we killed the PID or it was already killed and got an error,
                # in any case we remove it from the request list
                self.__ipToKillList.remove(badIP)
        except Exception as e:  # avoid catching exceptions like SystemExit, KeyboardInterrupt, etc.
            logging.exception("__processBadIPs(): Exception: " + str(e))
        finally:
            self.__mutex.release()

    # check active connections
    ##########################
    def __checkActiveConnections(self):
        self.__mutexActiveConn.acquire()
        try:
            # first clear list of connections...will be filled again
            ipConnectedList_old = self.__ipConnectedList
            self.__ipConnectedList = []
            # now check for connections which are currently established
            logging.debug("Checking active connections..")
            if os.geteuid() == 0:
                command = "netstat -anolp 2>/dev/null | grep -v unix | grep \"" + configuration.CONN_ESTABLISHED_STR + "\" | grep \""
                command = command + self.local + "\""
            else:
                # NOTE: with 2>/dev/null we throw away the std error,
                #       otherwise we constantly get errors in output
                command = "netstat -anolp 2>/dev/null | grep -v unix | grep \"" + configuration.CONN_ESTABLISHED_STR + "\" | grep \""
                command = command + self.local + "\""
            p1 = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
            out, err = p1.communicate()
            if p1.returncode == 0:
                p1.terminate()
                p1.kill()
                out = out.decode('utf-8')
                out = out.splitlines()
                for netstatLine in out:
                    line = str(netstatLine)
                    logging.debug(line)
                    posDoublePoint = find_2nd(line, ":")
                    posSpace = line.rfind(" ", posDoublePoint - 16, posDoublePoint)
                    activeIP = line[posSpace + 1:posDoublePoint]
                    if activeIP not in self.__ipConnectedList:
                        self.__ipConnectedList.append(activeIP)
                new_conn = [x for x in self.__ipConnectedList if x not in ipConnectedList_old]
                conn_rem = [x for x in ipConnectedList_old if x not in self.__ipConnectedList]
                if new_conn:
                    logging.info("New connection(s): " + str(new_conn))
                if conn_rem:
                    logging.info("Removed connection(s): " + str(conn_rem))
            else:
                p1.terminate()
                p1.kill()
                logging.error("Error: could not execute netstat correctly to find active connections with command = " + str(command))
            if configuration.SOUND and not configuration.ONLY_ALARMS_SOUND:
                playsound_block_false('IPRadar2/Sounds/smb_stomp.mp3')
            self.numberOfConnections = len(self.__ipConnectedList)
        except Exception as e:  # avoid catching exceptions like SystemExit, KeyboardInterrupt, etc.
            logging.exception("__checkActiveConnections(): Exception: " + str(e))
        finally:
            self.__mutexActiveConn.release()

    # process hosts in queue
    ########################
    def processingThread(self):
        # main loop
        ###########
        while True:
            # check active connections
            self.doCheckActiveConnections = not self.doCheckActiveConnections
            if self.doCheckActiveConnections:
                self.__checkActiveConnections()
            while not self.__badIPQueue.empty():
                ip = self.__badIPQueue.get(block=False)
                if ip != None:
                    if ip not in self.__ipToKillList:
                        self.__ipToKillList.append(ip)
            if self.doKillIPs == True:
                self.__processBadIPs()
            elif self.doKillAll == True:
                self.__killAll()
            sleep(configuration.CHECK_PERIOD_IN_SEC)

    # get connected IPs
    ###################
    def getConnectedIPs(self):
        ipConnectedListTemp = []
        self.__mutexActiveConn.acquire()
        try:
            if self.__ipConnectedList:
                ipConnectedListTemp = deepcopy(self.__ipConnectedList)
        except Exception as e:
            logging.exception("Exception in getConnectedIPs = " + str(e))
            ipConnectedListTemp = []
        finally:
            self.__mutexActiveConn.release()
        return ipConnectedListTemp

    # get killed hosts
    ##################
    def getKilledIPs(self):
        self.__mutex.acquire()
        try:
            if self.__ipKilledList:
                ipKilledListTemp = deepcopy(self.__ipKilledList)
                self.__ipKilledList = {}
            else:
                ipKilledListTemp = {}
        except Exception as e:
            logging.exception("Exception in getKilledIPs = " + str(e))
            ipKilledListTemp = {}
        finally:
            self.__mutex.release()
        return ipKilledListTemp

    # put bad IP to kill
    ####################
    def putIPToKill(self, ip):
        # try to resolve ONLY ONCE
        if ip not in self.__badIPQueue.queue:
            self.__badIPQueue.put(ip)
            self.countersLock.acquire()
            self.nrOfBadIPs = self.nrOfBadIPs + 1
            self.countersLock.release()

    def getNumberOfBadIPs(self):
        self.countersLock.acquire()
        # int is an immutable object so assignment will get a COPY of the value
        tempVal = self.nrOfBadIPs
        self.countersLock.release()
        return tempVal

    def getNumberOfIPsKilled(self):
        self.countersLock.acquire()
        # int is an immutable object so assignment will get a COPY of the value
        tempVal = len(self.__ipKilledListComplete)
        self.countersLock.release()
        return tempVal

    def getListOfKilledNodes(self):
        self.__mutex.acquire()
        try:
            if self.__ipKilledListComplete:
                ipKilledListCompleteTemp = deepcopy(self.__ipKilledListComplete)
            else:
                ipKilledListCompleteTemp = []
        except Exception as e:
            ipKilledListCompleteTemp = []
            logging.exception("Exception in getListOfKilledNodes = " + str(e))
        finally:
            self.__mutex.release()
        return ipKilledListCompleteTemp

    def killIPs(self):
        self.doKillIPs = True
        self.doKillAll = False

    def killAll(self):
        self.doKillIPs = False
        self.doKillAll = True

    def killNone(self):
        self.doKillIPs = False
        self.doKillAll = False

    # command to kill connections to bad IPs right now (only once)
    ##############################################################
    def killIPsNow(self):
        # TODO: check if trying to kill also connections which are not active
        self.__processBadIPs()

    # command to kill all active connections to known IPs right now (only once)
    ###########################################################################
    def killAllNow(self):
        self.__killAll()

    def killIP(self, ip):
        logging.info("Kill requested IP = " + ip)
        command = "netstat -anolp 2>/dev/null | grep -v unix | grep \"" + configuration.CONN_ESTABLISHED_STR + "\" | grep \""
        command = command + self.local + "\""
        command = command + " | grep \""
        command = command + ip + "\""
        p1 = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
        out, err = p1.communicate()
        if p1.returncode == 0:
            p1.terminate()
            p1.kill()
            out = out.decode('utf-8')
            out = out.splitlines()
            for netstatLine in out:
                line = str(netstatLine)
                logging.debug(line) # NOTE: too much info, not really needed...
                # TODO: improvement
                # find a way to get the PID of the "sub-process" so e.g. we dont shut down browser completely
                #############################################################################################
                pid = re.split(r' +', line)
                pid = pid[6]
                pid = pid[:pid.rfind('/')]
                try:
                    p = psutil.Process(int(pid))
                    pname = p.name()
                    # don't kill processes in white list
                    if pname not in configuration.WhiteListNotKill:
                        try:
                            p.kill()
                            if ip not in self.__ipKilledList:
                                self.__ipKilledList[ip] = pname
                            message = "Killed process " + pname + " with PID = " + pid + " holding a connection with passed IP = " + ip
                            logging.info(message)
                            self.__ipKilledListComplete.append(pname + " (" + ip + ")")
                            if configuration.SOUND and not configuration.ONLY_ALARMS_SOUND:
                                playsound_block_false('IPRadar2/Sounds/smb_bowserfalls.mp3')
                        except:
                            logging.exception("Could NOT kill PID = " + str(pid))
                    else:
                        logging.info("Did NOT kill process " + pname + " with PID = " + pid + " holding a connection with passed IP = " + ip + " because it is in the white-list!")
                except:
                    logging.exception("Could not get PID from process to kill.")

    def getNumberOfConnections(self):
        return self.numberOfConnections
