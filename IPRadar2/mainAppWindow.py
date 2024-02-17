import gc
import sys
import time

if "IPRadar2" in str(sys.argv):
    import configuration
    import helper_functions as hf
    from Ui_mainWindow import Ui_MainWindow
    from pysharkSniffer import pysharkSnifferClass
else:
    from IPRadar2 import configuration
    import IPRadar2.helper_functions as hf
    from IPRadar2.Ui_mainWindow import Ui_MainWindow
    from IPRadar2.pysharkSniffer import pysharkSnifferClass

from PyQt5.QtCore import pyqtSlot, QFileInfo, QModelIndex, QThread, pyqtSignal
from PyQt5.QtWidgets import QMainWindow, QFileDialog, QListWidgetItem
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import QMessageBox
import PyQt5.QtCore as QtCore
import shlex, subprocess
from time import sleep, gmtime, strftime
import os
from pathlib import Path
import threading
import pwd
import logging
import webbrowser



class MyMainWindow(QMainWindow, Ui_MainWindow):
    listOfHosts = []
    sniffer = pysharkSnifferClass()
    fpath = "/"
    tsharkInterfaces = None
    tsharkInterfacesList = []
    currentInterface = None
    toggle = 0
    node_dict_gui = {}  # complete dict of nodes
    item_index = {}  # IP -> index
    selected_ip = ""
    indexCount = 0  # count item in self.listWidgetNodes
    status = ["/", "-", "\\", "|"]
    statusCnt = 0
    top = True
    create_report_file = False

    @pyqtSlot()
    def closeEvent(self, event):
        logging.info("mainWindow closing..")
        if self.pbLiveCapture.text() == "exit" or self.pbOpenFile.text() == "exit":
            self.createReportFile()
            self.generateIps()
            #################
            currentTime = strftime("%Y.%m.%d %H:%M:%S", gmtime())
            self.setWindowTitle("IPRadar2 - capture finished on " + currentTime)
            logging.info("Bye!")
        self.sniffer.processorObject.close()
        while(self.sniffer.processorObject.close_app == False):
            time.sleep(0.1)
        # WORKAROUND: until we release resources properly...not nice, but it works
        if "IPRadar2" not in str(sys.argv):
            p1 = subprocess.Popen(shlex.split("pkill -SIGKILL ipradar2"))
            p1.wait()
            p1.terminate()
            p1.kill()
        raise Exception("Exit application..")
        self.close()

    #################################
    # IMPORTANT: we don't modify GUI objects from a QThread
    #            or even worse, from a python thread!
    #            Instead, we send a signal to the GUI / MainWindow.
    # Ref.: https://stackoverflow.com/questions/12083034/pyqt-updating-gui-from-a-callback
    #################################
    class MyGuiUpdateThread(QThread):
        updated = pyqtSignal(str)
        close_QThread = False

        def run(self):
            while self.close_QThread is False:
                sleep(configuration.CHECK_PERIOD_IN_SEC * 2.0)
                self.updated.emit("Hi")
            logging.info("Leaving MyGuiUpdateThread.run()..")

        def close_gui_thread(self):
            self.close_QThread = True

    # thread to update GUI
    ######################
    def updateGui(self):
        # update status on GUI
        ######################
        if self.lblStatus is not None:
            # set alternating color
            if self.statusCnt % 2:
                self.lblStatus.setStyleSheet("".join(['QLabel {background-color: ' , "lightgreen" , '; border: 1px solid black}']))
            else:
                self.lblStatus.setStyleSheet("".join(['QLabel {background-color: ' , "lightgray" , '; border: 1px solid black}']))
            # set alternating symbol
            self.lblStatus.setText("".join([" " , self.status[self.statusCnt]]))
            self.statusCnt = (self.statusCnt + 1) % 4

        # update counters
        #################
        self.statusHostsRequested.setText(
            str(self.sniffer.getNumberOfHostsRequested()))
        self.statusHostsSolved.setText(
            str(self.sniffer.getNumberOfHostsSolved()))
        self.statusHostsFailed.setText(
            str(self.sniffer.getNumberOfHostsFailed()))
        self.statusConnections.setText(
            str(self.sniffer.getNumberOfConnections()))
        self.statusNodes.setText(str(self.sniffer.getNumberOfNodes()))
        self.statusBadNodes.setText(str(self.sniffer.getNumberOfBadNodes()))

        # nodes
        #######
        nodes = self.sniffer.getDictOfNodes()
        if nodes:
            for key, value in nodes.items():
                if key in self.node_dict_gui:
                    # update list with modified item
                    currIdx = self.item_index[key]
                    guiString = str(value)[str(value).find("pos") + 4:]
                    self.listWidgetNodes.item(currIdx).setText(guiString)
                    if value.killed:
                        self.listWidgetNodes.item(
                            currIdx).setBackground(QColor('pink'))
                    elif value.local:
                        self.listWidgetNodes.item(currIdx).setBackground(
                            QColor('lightblue'))  # ('blue'))
                    elif value.bad:
                        self.listWidgetNodes.item(currIdx).setBackground(
                            QColor('red'))
                    elif value.host_resolved == False:
                        self.listWidgetNodes.item(
                            currIdx).setBackground(QColor('yellow'))
                    elif value.ping == False:
                        self.listWidgetNodes.item(
                            currIdx).setBackground(QColor('lightyellow'))
                    else:
                        self.listWidgetNodes.item(
                            currIdx).setBackground(QColor('lightgreen'))
                    font = QFont()
                    if value.conn_established:
                        font.setBold(True)
                    else:
                        font.setBold(False)
                    self.listWidgetNodes.item(currIdx).setFont(font)
                else:
                    # update list with new item
                    new_item = QListWidgetItem()
                    guiString = str(value)[str(value).find("pos") + 4:]
                    new_item.setText(guiString)
                    if value.killed:
                        new_item.setBackground(QColor('pink'))
                    elif value.local:
                        new_item.setBackground(
                            QColor('lightblue'))
                    elif value.bad:
                        new_item.setBackground(QColor('red'))
                    elif value.host_resolved == False:
                        new_item.setBackground(QColor('yellow'))
                    elif value.ping == False:
                        new_item.setBackground(QColor('lightyellow'))
                    else:
                        new_item.setBackground(QColor('lightgreen'))
                    font = QFont()
                    if value.conn_established:
                        font.setBold(True)
                    else:
                        font.setBold(False)
                    new_item.setFont(font)
                    new_item.setFlags(
                        new_item.flags() | QtCore.Qt.ItemIsUserCheckable)
                    new_item.setCheckState(QtCore.Qt.Checked)
                    self.listWidgetNodes.addItem(new_item)
                    # auto-scroll
                    if configuration.AUTO_SCROLL_NODE_LIST:
                        self.listWidgetNodes.scrollToBottom()
                    # store dict element: IP -> index to be able to access
                    # listWidgetNodes element using IP
                    self.item_index[key] = self.indexCount
                    self.indexCount = self.indexCount + 1

                # new IPs added to combo-box
                ############################
                if key not in self.node_dict_gui:
                    self.comboPing.addItem(key)
                    # and select it in order to show it
                    if self.cbPingIP.isChecked() == False:
                        self.comboPing.setCurrentIndex(self.comboPing.count() - 1)
                # add/modify node to module dict
                self.node_dict_gui[key] = value

                # add new host (owner name) ?
                #############################
                if str(value.whosip).find("Owner Name:") != -1:
                    startIndex = str(value.whosip).find("Owner Name:") + 11
                    hostTextFromOnwerName = str(value.whosip)[startIndex:]
                    if hostTextFromOnwerName not in self.listOfHosts:
                        self.listOfHosts.append(hostTextFromOnwerName)
                        self.comboShowHost.addItem(hostTextFromOnwerName)
                        # update text in GUI
                        self.comboShowHost.updateText()

            # set flag to create(update) report file
            ########################################
            self.create_report_file = True

            # update combo-box with current connections
            ###########################################
            selectedIpTemp = str(self.comboKill.currentText())
            self.comboKill.clear()
            for key, value in self.node_dict_gui.items():
                if value.conn_established:
                    self.comboKill.addItem(key)
                    # and select it in order to show it
                    if (self.cbKillIP.isChecked() == False) or (
                            key == selectedIpTemp):
                        self.comboKill.setCurrentIndex(
                            self.comboKill.count() - 1)

        # questions to add firewall rules
        #################################
        listOfQuestions = self.sniffer.getListOfFirewallQuestions()
        if listOfQuestions:
            for question in listOfQuestions:
                if hf.show_popup_question("".join(["Add rule to block bad IP?\n" , question.infos])) == QMessageBox.Yes:
                    self.sniffer.addDenyFirewallRule(question.ip)

        # killed nodes
        ##############
        nrKilledNodes = self.sniffer.getNumberOfKilledNodes()
        if nrKilledNodes > self.listWidgetKilledProcesses.count():
            self.statusKilledNodes.setText(str(nrKilledNodes))
            listKilledNodes = self.sniffer.getListOfKilledNodes()
            for i in range(
                    nrKilledNodes -
                    self.listWidgetKilledProcesses.count()):
                new_item = QListWidgetItem()
                new_item.setText(listKilledNodes[nrKilledNodes - i - 1])
                self.listWidgetKilledProcesses.addItem(new_item)

        # TX max limit alarm handling
        #############################
        txKiloBytes = self.sniffer.getNumberOfTxKiloBytes()
        if txKiloBytes > configuration.MAX_TX_KILOBYTES:
            if self.toggle == 0:
                self.statusTxBytes.setStyleSheet('color: red')
                self.labelTXBytes.setStyleSheet('color: red')
            else:
                self.statusTxBytes.setStyleSheet('color: black')
                self.labelTXBytes.setStyleSheet('color: black')
            self.toggle = not self.toggle
        self.statusTxBytes.setText(str(txKiloBytes))
        rxKiloBytes = self.sniffer.getNumberOfRxKiloBytes()
        self.statusRxBytes.setText(str(rxKiloBytes))
        self.statusRxTxBytes.setText(str(rxKiloBytes + txKiloBytes))

        # statistics of packets (input, processed, queued)
        in_packets = self.sniffer.getNumberOfInPackets()
        processed_packets = self.sniffer.getNumberOfProcessedPackets()
        self.statusInPackets.setText(str(in_packets))
        self.statusProcessedPackets.setText(str(processed_packets))
        # self.statusQueuedPackets.setText(str(self.sniffer.getNumberOfQueuedPackets()))
        self.statusQueuedPackets.setText(str(in_packets - processed_packets))

    def threadCreateReportFile(self):
        while True:
            if self.create_report_file:
                self.create_report_file = False
                self.createReportFile()
                self.generateIps()
            sleep(configuration.CHECK_PERIOD_IN_SEC * 10.0)

    def __init__(self):
        super(MyMainWindow, self).__init__()
        self.setupUi(self)
        self.setFixedSize(self.size())
        currentTime = strftime("%Y.%m.%d - %H:%M:%S", gmtime())
        userStr = "user: " + pwd.getpwuid(os.getuid()).pw_name
        self.setWindowTitle("".join(["IPRadar2  (" , currentTime , ")  " , userStr]))
        # fill combo-box with tshark interfaces
        self.currentInterface = configuration.INTERFACE
        self.tsharkInterfaces = self.sniffer.getInterfaces()
        interfaceNr = 1
        for interface in self.tsharkInterfaces:
            self.comboBoxInterface.addItem("".join([str(interfaceNr) , ". " , " " , interface]))
            self.tsharkInterfacesList.append(interface)
            # is config IF? then set
            if self.currentInterface in interface:
                self.comboBoxInterface.setCurrentIndex(interfaceNr)
                self.comboBoxInterface.setCurrentText("".join([str(interfaceNr) , ". " , " " , interface]))
            interfaceNr = interfaceNr + 1

        # select default interface
        ##########################
        if configuration.INTERFACE != "":
            # configured interface also selected?
            # if not set in combo-box
            if configuration.INTERFACE in self.comboBoxInterface.currentText():
                # config interface is same as selected
                pass
            else:
                index = self.comboBoxInterface.currentIndex()
                self.currentInterface = self.tsharkInterfacesList[index]
        else:
            # default first interface
            self.currentInterface = self.tsharkInterfacesList[0]
            # now fix some things
            configuration.INTERFACE = self.tsharkInterfacesList[0]
            self.sniffer.set_netmask()

        # set colors
        ############
        self.listWidgetKilledProcesses.setStyleSheet("background-color: lightGray")
        self.listWidgetKilledProcesses.setSelectionMode(self.listWidgetKilledProcesses.SingleSelection)
        self.listWidgetNodes.setStyleSheet("background-color: lightGray")
        self.listWidgetNodes.setSelectionMode(self.listWidgetNodes.SingleSelection)
        self.ptSelectedIP.setStyleSheet("background-color: lightGray")
        self.comboShowHost.setStyleSheet("background-color: lightGray")

        # init states
        #############
        self.pbWhois.setToolTip("Information of selected IP.\nGenerate and open file with information of currently selected IP.")
        self.cbStayOnTop.setChecked(configuration.MAIN_WINDOW_ON_TOP)
        self.cbStayOnTop.setEnabled(False)
        self.cbStayOnTop.setToolTip("This setting can be changed with MAIN_WINDOW_ON_TOP in config.ini")
        if configuration.MAIN_WINDOW_ON_TOP:
            self.setWindowFlags(self.windowFlags() | QtCore.Qt.WindowStaysOnTopHint)
        else:
            self.setWindowFlags(self.windowFlags() & QtCore.Qt.WindowStaysOnBottomHint)
        self.pbRules.setToolTip("Generate and open rules file.\nFor security reasons this file is not generated automatically.")
        self.pbStartIpNetInfo.setToolTip("Update and open file with IP addresses.")
        self.pbGenerateReport.setToolTip("Update and open .csv report file.")
        if os.geteuid() == 0:
            self.pbShowMap.setEnabled(False)
            self.pbShowMap.setToolTip('Action not possible as root. Please open IPRadar2//Output/mapxxxx.html on your browser')
            self.cbSound.setChecked(False)
            self.cbSound.setEnabled(False)
            self.cbSound.setToolTip('Playing multiple sounds at the same time when running as root is not possible.')
        else:
            self.pbRules.setEnabled(False)
            self.pbRules.setToolTip('Action only possible as root. Try instead on a terminal: sudo ufw status')
            self.cbSound.setChecked(configuration.SOUND)
        self.cbAlarmsOnly.setChecked(configuration.ONLY_ALARMS_SOUND)
        self.pbKill.setEnabled(False)
        self.pbPing.setEnabled(False)
        self.cbShowPopups.setChecked(False)
        self.cbShowBad.setChecked(configuration.SHOW_HOST_BAD)
        self.cbShowKilled.setChecked(configuration.SHOW_HOST_KILLED)
        self.cbShowActive.setChecked(configuration.SHOW_HOST_ACTIVE)
        self.cbShowMarkers.setChecked(configuration.SHOW_NODES)
        self.cbShowLabels.setChecked(configuration.SHOW_LABELS)
        self.cbShowConnections.setChecked(configuration.SHOW_CONNECTIONS)
        self.cbShowConnectionsActive.setChecked(configuration.SHOW_CONNECTIONS_ACTIVE)
        self.cbShowInfo.setChecked(configuration.SHOW_INFO)
        self.cbShowGood.setChecked(configuration.SHOW_HOST_GOOD)
        self.cbShowUnresolved.setChecked(configuration.SHOW_HOST_UNKNOWN)
        self.cbShowBadConn.setChecked(configuration.SHOW_CONNECTION_BAD)
        self.cbShowKilledConn.setChecked(configuration.SHOW_CONNECTION_KILLED)
        self.cbShowGoodConn.setChecked(configuration.SHOW_CONNECTION_GOOD)
        self.cbShowUnresolvedConn.setChecked(configuration.SHOW_CONNECTION_UNKNOWN)
        self.cbPlot.setChecked(configuration.PLOT)
        self.cbKillBad.setChecked(False)
        self.cbKillBandwidth.setEnabled(False)
        self.cbKillBandwidth.setToolTip('Feature not yet implemented!')
        self.cbShowPing.setChecked(True)
        self.sniffer.pingAuto(self.cbPingAuto.isChecked())
        self.cbPingAuto.setEnabled(self.cbPingAuto.isChecked())
        self.cbPingAuto.setToolTip("Ping every new host automatically.")
        self.cbPingIP.setChecked(True)
        self.cbKillIP.setChecked(True)
        self.pbTraceroute.setToolTip("Warning! This action may take some time.\nThe results will be shown as soon as available.")
        self.cbAutoScrollNodes.setChecked(configuration.AUTO_SCROLL_NODE_LIST)
        self.statusHostsFailedOld.setText(str(self.sniffer.getHostsFailedPast()))
        self.statusHostsResolvedOld.setText(str(self.sniffer.getHostsResolvedPast()))
        self.ptSelectedIP.textCursor().setKeepPositionOnInsert(True)
        self.cbPingRandom.setText("".join([str(configuration.NR_OF_RANDOM_IPS_TO_PING) , " random IPs"]))
        self.cbBlockBadInFirewall.setChecked(configuration.ADD_FIREWALL_RULE_BLOCK_BAD_IP)
        # if not root we disable option to add firewall rules
        if os.geteuid() != 0:
            self.cbBlockBadInFirewall.setChecked(False)
            self.cbBlockBadInFirewall.setEnabled(False)
        self.cbAskBeforeAddingRule.setChecked(configuration.ASK_BEFORE_ADDING_RULE)
        self.cbAskBeforeKill.setChecked(configuration.ASK_BEFORE_KILL)

        # create thread to update report files periodically
        ###################################################
        threadCreateReportFile = threading.Thread(name="threadCreateReportFile", target=self.threadCreateReportFile)
        threadCreateReportFile.start()

        # create QThread to upate GUI perdiodically
        ###########################################
        self._thread = self.MyGuiUpdateThread(self)
        self._thread.updated.connect(self.updateGui)
        self._thread.start()

    def createReportFile(self):
        reportFileString = "".join(['./IPRadar2/Output/report_' , configuration.START_TIME , '.csv'])
        reportFile = None
        try:
            reportFile = open(reportFileString, "w", encoding="utf-8")
            for itemIndex in range(self.listWidgetNodes.count()):
                reportFile.write("".join([self.listWidgetNodes.item(itemIndex).text() , "\n"]))
            reportFile.write("\n")
            reportFile.close()
            logging.debug("Created Report File.")
        except Exception as e:
            if reportFile is not None:
                reportFile.close()
            logging.exception("Exception: mainWindow.createReportFile() exception = " + str(e))

    # TODO: ckeck why this is not working
    @pyqtSlot()
    def on_cbStayOnTop_clicked(self):
        flags = self.windowFlags()
        if self.cbStayOnTop.isChecked():
            flags ^= QtCore.Qt.WindowStaysOnBottomHint
            flags |= QtCore.Qt.WindowStaysOnTopHint
        else:
            flags ^= QtCore.Qt.WindowStaysOnTopHint
            flags |= QtCore.Qt.WindowStaysOnBottomHint
        self.setWindowFlags(flags)
        self.show()

    @pyqtSlot()
    def on_pbLiveCapture_clicked(self):
        if self.pbLiveCapture.text() == "exit":
            self.pbLiveCapture.setEnabled(False)
            self.close()
        else:
            self.pbOpenFile.setEnabled(False)
            self.comboBoxInterface.setEnabled(False)
            self.sniffer.sniff(self.currentInterface)
            # deactivate button
            self.pbLiveCapture.setText("exit")
            self.pbKill.setEnabled(True)
            self.pbPing.setEnabled(True)
            currentTime = strftime("%Y.%m.%d %H:%M:%S", gmtime())
            self.setWindowTitle("IPRadar2 - capture started on " + currentTime)

    @pyqtSlot()
    def on_pbOpenFile_clicked(self):
        if self.pbOpenFile.text() == "exit":
            self.close()
        else:
            fname = QFileDialog.getOpenFileName(
                self, 'Open file', self.fpath, "Packet capture file (*.pcapng *.pcap *.cap)")
            if len(fname) != 0:
                fname = fname[0]
                if fname != "":
                    fileNameInfo = QFileInfo(fname)
                    # use same folder in next call
                    self.fpath = fileNameInfo.absolutePath()
                    self.sniffer.sniff(0, fname)
                    self.pbLiveCapture.setEnabled(False)
                    self.pbOpenFile.setEnabled(False)
                    self.comboBoxInterface.setEnabled(False)
                    self.pbOpenFile.setEnabled(True)
                    self.pbOpenFile.setText("open file")

    @pyqtSlot()
    def on_cbShowPopups_clicked(self):
        configuration.SHOW_POPUPS = not configuration.SHOW_POPUPS

    @pyqtSlot()
    def on_cbShowBad_clicked(self):
        self.sniffer.toggleShowBadHosts()

    @pyqtSlot()
    def on_cbShowMarkers_clicked(self):
        self.sniffer.toggleShowNodes()

    @pyqtSlot()
    def on_cbShowLabels_clicked(self):
        self.sniffer.toggleShowLabels()

    @pyqtSlot()
    def on_cbShowConnections_clicked(self):
        self.sniffer.toggleShowConnections()

    @pyqtSlot()
    def on_cbShowInfo_clicked(self):
        self.sniffer.toggleShowInfo()

    @pyqtSlot()
    def on_cbShowGood_clicked(self):
        self.sniffer.toggleShowGoodHosts()

    @pyqtSlot()
    def on_cbShowUnresolved_clicked(self):
        self.sniffer.toggleShowUnknownHosts()

    @pyqtSlot()
    def on_cbShowGoodConn_clicked(self):
        self.sniffer.toggleShowGoodConnections()

    @pyqtSlot()
    def on_cbShowUnresolvedConn_clicked(self):
        self.sniffer.toggleShowUnknownConnections()

    @pyqtSlot()
    def on_cbShowBadConn_clicked(self):
        self.sniffer.toggleShowBadConnections()

    @pyqtSlot()
    def on_centralWidget_destroyed(self):
        logging.info("mainWindow destroyed!")

    @pyqtSlot()
    def on_cbPlot_clicked(self):
        self.sniffer.setPlot(self.cbPlot.isChecked())

    @pyqtSlot()
    def on_cbSound_clicked(self):
        self.sniffer.setSound(self.cbSound.isChecked())

    @pyqtSlot()
    def on_cbAlarmsOnly_clicked(self):
        self.sniffer.setAlarmsOnly(self.cbAlarmsOnly.isChecked())

    @pyqtSlot(str)
    def on_comboBoxInterface_currentIndexChanged(self, p0):
        selectedIF = self.comboBoxInterface.currentIndex()
        if selectedIF != 0:
            self.currentInterface = self.tsharkInterfacesList[selectedIF]
            logging.info("".join(["Selected capture interface = " , str(self.currentInterface)]))

    # change SETTINGS for killing automatically
    def killSetting(self):
        if self.cbKillBad.isChecked():
            # kill connections to bad IPs
            self.sniffer.killIPs()
        elif self.cbKillAll.isChecked():
            # kill all active connections
            self.sniffer.killAll()
        elif self.cbKillBandwidth.isChecked():
            # TODO: implement feature..
            pass
        elif self.cbKillNone.isChecked():
            # don't kill anybody
            self.sniffer.killNone()

    @pyqtSlot()
    def on_cbKillNone_clicked(self):
        self.killSetting()
        self.cbKillBad.setStyleSheet('color: black')
        # TODO: put back when feature implemented
        #       self.cbKillBandwidth.setStyleSheet('color: black')
        self.cbKillAll.setStyleSheet('color: black')

    @pyqtSlot()
    def on_cbKillBad_clicked(self):
        self.cbKillBad.setStyleSheet('color: red')
        # TODO: put back when feature implemented
        #       self.cbKillBandwidth.setStyleSheet('color: black')
        self.cbKillAll.setStyleSheet('color: black')
        if configuration.ASK_BEFORE_KILL is False:
            self.killSetting()
        elif hf.show_popup_question("Do you want to kill all bad processes with active connections?") == QMessageBox.Yes:
            self.killSetting()
        else:
            self.cbKillNone.setChecked(True)

    @pyqtSlot()
    def on_cbKillBandwidth_clicked(self):
        self.cbKillBad.setStyleSheet('color: black')
        # TODO: put back when feature implemented
        #       self.cbKillBandwidth.setStyleSheet('color: red')
        self.cbKillAll.setStyleSheet('color: black')
        if configuration.ASK_BEFORE_KILL is False:
            self.killSetting()
        elif hf.show_popup_question("Do you want to kill all processes with active connections which exceeded the bandwidth limit?") == QMessageBox.Yes:
            self.killSetting()
        else:
            self.cbKillNone.setChecked(True)

    @pyqtSlot()
    def on_cbKillAll_clicked(self):
        self.cbKillBad.setStyleSheet('color: black')
        # TODO: put back when feature implemented
        #       self.cbKillBandwidth.setStyleSheet('color: black')
        self.cbKillAll.setStyleSheet('color: red')
        if configuration.ASK_BEFORE_KILL is False:
            self.killSetting()
        elif hf.show_popup_question("Do you want to kill all processes with active connections?") == QMessageBox.Yes:
            self.killSetting()
        else:
            self.cbKillNone.setChecked(True)

    @pyqtSlot()
    def on_cbShowConnectionsActive_clicked(self):
        self.sniffer.toggleShowConnectionsActive()

    @pyqtSlot()
    def on_pbGenerateReport_clicked(self):
        currAbsPath = Path().absolute()
        currAbsPath = str(currAbsPath)
        reportFileString = os.path.join(currAbsPath, "".join([currAbsPath , "/IPRadar2/Output/report_" , configuration.START_TIME , ".csv"]))
        if os.path.isfile(reportFileString):
            self.createReportFile()
            subprocess.call(["open", reportFileString])
        else:
            hf.show_popup_warning("Report file not crated.\nNo data available yet!")
        return

    @pyqtSlot()
    def on_cbPingAll_clicked(self):
        self.cbPingRandom.setStyleSheet('color: black')

    @pyqtSlot()
    def on_cbPingRandom_clicked(self):
        if self.cbPingRandom.isChecked():
            self.cbPingRandom.setStyleSheet('color: red')
        else:
            self.cbPingRandom.setStyleSheet('color: black')

    @pyqtSlot()
    def on_cbPingIP_clicked(self):
        self.cbPingRandom.setStyleSheet('color: black')

    def PingAllThread(self):
        self.sniffer.pingAll()

    def PingRandomThread(self):
        self.sniffer.pingRandom()

    @pyqtSlot()
    def on_pbPing_clicked(self):
        # ping All
        if self.cbPingAll.isChecked():
            pingAllThread = threading.Thread(name="pingAllThread", target=self.PingAllThread)
            pingAllThread.start()
        # ping NR_OF_RANDOM_IPS_TO_PING random IPs:
        elif self.cbPingRandom.isChecked():
            if self.cbBlockBadInFirewall.isChecked():
                doReturn = hf.show_popup_question(
                    "If bad IPs are pinged, they will be added to the firewall, are you sure you want to proceed?\nWarning! Firewall rule may be added automatically.")
                if doReturn != QMessageBox.Yes:
                    return
            pingRandomThread = threading.Thread(name="pingRandomThread", target=self.PingRandomThread)
            pingRandomThread.start()
        # ping selected IP:
        else:
            if self.comboPing.currentText() != "":
                self.sniffer.pingIP(self.comboPing.currentText())

    @pyqtSlot()
    def on_cbPingAuto_clicked(self):
        self.sniffer.pingAuto(self.cbPingAuto.isChecked())

    @pyqtSlot()
    def on_cbShowPing_clicked(self):
        self.sniffer.toggleShowPingedNegHosts()

    @pyqtSlot(str)
    def on_comboPing_currentIndexChanged(self, p0):
        # don't do anything for now...
        return

    @pyqtSlot()
    def on_pbKill_clicked(self):
        if self.cbKillAllNow.isChecked():
            # kill all active connections
            if configuration.ASK_BEFORE_KILL is False:
                self.sniffer.killAllNow()
            elif hf.show_popup_question("Do you want to kill all processes with active connections?") == QMessageBox.Yes:
                self.sniffer.killAllNow()
        elif self.cbKillBadNow.isChecked():
            # kill only active connections to bad IPs
            if configuration.ASK_BEFORE_KILL is False:
                self.sniffer.killIPsNow()
            elif hf.show_popup_question("Do you want to kill all processes with active connections to bad IPs?") == QMessageBox.Yes:
                self.sniffer.killIPsNow()
        else:
            # kill connection to specified IP
            if self.comboKill.currentText() != "":
                ip_to_kill = self.comboKill.currentText()
                if configuration.ASK_BEFORE_KILL is False:
                    self.sniffer.killIP(ip_to_kill)
                elif hf.show_popup_question("Do you want to kill all processes with an active connection to IP = " + ip_to_kill) == QMessageBox.Yes:
                    self.sniffer.killIP(ip_to_kill)

    @pyqtSlot()
    def on_cbShowKilled_clicked(self):
        self.sniffer.toggleShowKilledHosts()

    @pyqtSlot()
    def on_cbShowActive_clicked(self):
        self.sniffer.toggleShowActiveHosts()

    @pyqtSlot()
    def on_cbShowKilledConn_clicked(self):
        self.sniffer.toggleShowKilledConnections()

    @pyqtSlot()
    def on_pbSelectAll_clicked(self):
        show = True
        for i in range(self.listWidgetNodes.count()):
            self.listWidgetNodes.item(i).setCheckState(QtCore.Qt.CheckState.Checked)
        # TODO: check why this is not working:
        # for item in self.listWidgetNodes.items():
        # item.setCheckState(show)
        self.sniffer.showAllHosts(show)

    @pyqtSlot()
    def on_pbClearAll_clicked(self):
        show = False
        for i in range(self.listWidgetNodes.count()):
            self.listWidgetNodes.item(i).setCheckState(QtCore.Qt.CheckState.Unchecked)
        self.sniffer.showAllHosts(show)

    @pyqtSlot(QListWidgetItem)
    def on_listWidgetNodes_itemClicked(self, item):
        start_index = item.text().find("ip='") + 4
        end_index = item.text()[start_index:].find("'")
        selected_ip = item.text()[start_index:start_index + end_index]
        if selected_ip == self.selected_ip:
            self.listWidgetNodes.clearSelection()
            self.selected_ip = ""
            self.sniffer.clearSelectedIp()
        else:
            self.ptSelectedIP.document().setPlainText(item.text().replace(",", "\n"))
            self.selected_ip = selected_ip
            self.listWidgetNodes.setCurrentItem(item)
            show = (self.listWidgetNodes.currentItem().checkState() == QtCore.Qt.Checked)
            # TODO: check why this is not working
            # show = (item.chekState()==QtCore.Qt.Checked)
            self.sniffer.updateShowNotShowHost(self.selected_ip, show)

    @pyqtSlot()
    def on_listWidgetKilledProcesses_itemSelectionChanged(self):
        startiIx = self.listWidgetKilledProcesses.currentItem().text().find("(") + 1
        endiIx = self.listWidgetKilledProcesses.currentItem().text().find(")")
        ip = self.listWidgetKilledProcesses.currentItem().text()[startiIx:endiIx]
        if ip in self.item_index:
            self.listWidgetNodes.setCurrentItem(self.listWidgetNodes.item(self.item_index[ip]))
            self.ptSelectedIP.document().setPlainText(self.listWidgetNodes.item(self.item_index[ip]).text().replace(",", "\n"))
            self.listWidgetNodes.scrollToItem(self.listWidgetNodes.item(self.item_index[ip]))

    @pyqtSlot(QModelIndex)
    def on_listWidgetKilledProcesses_clicked(self, index):
        self.on_listWidgetKilledProcesses_itemSelectionChanged()

    @pyqtSlot()
    def on_cbAutoScrollNodes_clicked(self):
        configuration.AUTO_SCROLL_NODE_LIST = self.cbAutoScrollNodes.isChecked()

    @pyqtSlot(str)
    def on_comboShowHost_currentTextChanged(self, p0):
        logging.info("Owner Name CHANGED:")
        logging.info(self.comboShowHost.currentData())
        s = set(self.comboShowHost.currentData())
        diff = [x for x in self.listOfHosts if x not in s]
        logging.info("".join(["List of NOT found hosts = " , str(diff)]))
        # update nodes
        self.sniffer.updateShowNotShowOwners(self.comboShowHost.currentData(), diff)
        self.comboShowHost.updateText()

    @pyqtSlot()
    def on_cbBlockBadInFirewall_clicked(self):
        self.sniffer.setBlockBadInFirewall(self.cbBlockBadInFirewall.isChecked())
        if self.cbBlockBadInFirewall.isChecked():
            self.cbBlockBadInFirewall.setStyleSheet('color: red')
        else:
            self.cbBlockBadInFirewall.setStyleSheet('color: black')

    @pyqtSlot()
    def on_cbAskBeforeAddingRule_clicked(self):
        configuration.ASK_BEFORE_ADDING_RULE = self.cbAskBeforeAddingRule.isChecked()

    @pyqtSlot()
    def on_cbAskBeforeKill_clicked(self):
        configuration.ASK_BEFORE_KILL = self.cbAskBeforeKill.isChecked()

    @pyqtSlot()
    def on_pbShowMap_clicked(self):
        # NOTE: alternative call: self.sniffer.processorObject.m.show_in_browser()
        webbrowser.open("".join(["IPRadar2/Output/map_" , configuration.START_TIME , ".html"]), new=2)

    @pyqtSlot()
    def on_pbStartIpNetInfo_clicked(self):
        if self.indexCount != 0:
            ipNetInfoThread = threading.Thread(name="ipNetInfoThread", target=self.IpNetInfoThread)
            ipNetInfoThread.start()
        else:
            hf.show_popup_warning("The list of hosts is currently empty.\nNo items available!")

    @pyqtSlot()
    def on_pbRules_clicked(self):
        rulesThread = threading.Thread(name="rulesThread", target=self.rulesThread)
        rulesThread.start()

    def rulesThread(self):
        # create rules.txt
        rules_file_name = "".join(["IPRadar2/Output/rules_" , configuration.START_TIME , ".txt"])
        command = "ufw status > " + rules_file_name
        p1 = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
        p1.communicate()
        if p1.returncode == 0:
            p1.terminate()
            p1.kill()
            if os.path.isfile(rules_file_name):
                subprocess.call([configuration.TEXT_EDITOR, rules_file_name])
        else:
            p1.terminate()
            p1.kill()
            logging.error("Error: could not generate rules file!")

    @pyqtSlot()
    def on_pbWhois_clicked(self):
        whoisThread = threading.Thread(name="whoisThread", target=self.whoisThread)
        whoisThread.start()

    def whoisThread(self):
        if self.selected_ip != "":
            # create whois_IP.txt
            whois_file_name = "".join(["IPRadar2/Output/whois_" , self.selected_ip , ".txt"])
            command = "".join(["whois " , self.selected_ip , " > " , whois_file_name])
            p1 = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
            p1.communicate()
            if p1.returncode == 0:
                p1.terminate()
                p1.kill()
                if os.path.isfile(whois_file_name):
                    subprocess.call([configuration.TEXT_EDITOR, whois_file_name])
            else:
                p1.terminate()
                p1.kill()
                logging.error("Error: could not generate whois file for IP = " + self.selected_ip)

    @pyqtSlot()
    def on_pbNetstat_clicked(self):
        netstatThread = threading.Thread(name="netstatThread", target=self.netstatThread)
        netstatThread.start()

    def netstatThread(self):
        if self.selected_ip != "":
            # create netstat_IP.txt
            netstat_file_name = "".join(["IPRadar2/Output/netstat_" , self.selected_ip , ".txt"])
            command = "".join(["netstat -anolp 2>/dev/null | grep -v unix | grep " , self.selected_ip , " > " , netstat_file_name])
            p1 = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
            p1.communicate()
            if p1.returncode == 0:
                p1.terminate()
                p1.kill()
                if os.path.isfile(netstat_file_name):
                    subprocess.call([configuration.TEXT_EDITOR, netstat_file_name])
            else:
                p1.terminate()
                p1.kill()
                logging.error("Error: could not generate netstat file for IP = " + self.selected_ip)

    @pyqtSlot()
    def on_pbTraceroute_clicked(self):
        tracerouteThread = threading.Thread(name="tracerouteThread", target=self.tracerouteThread)
        tracerouteThread.start()

    def tracerouteThread(self):
        if self.selected_ip != "":
            # create traceroute_IP.txt
            traceroute_file_name = "".join(["IPRadar2/Output/traceroute_" , self.selected_ip , ".txt"])
            command = "".join(["traceroute " , self.selected_ip , " > " , traceroute_file_name])
            p1 = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
            p1.communicate()
            if p1.returncode == 0:
                p1.terminate()
                p1.kill()
                if os.path.isfile(traceroute_file_name):
                    subprocess.call([configuration.TEXT_EDITOR, traceroute_file_name])
            else:
                p1.terminate()
                p1.kill()
                logging.error("Error: could not generate traceroute file for IP = " + self.selected_ip)

    def generateIps(self):
        # create ips.txt
        ip_file_name = "".join(["IPRadar2/Output/ips_" , configuration.START_TIME , ".txt"])
        f = open(ip_file_name, "w", encoding="utf-8")
        if self.rbSelectedIpInfos.isChecked():
            # default value
            ip = configuration.PUBLIC_IP
            if self.listWidgetNodes.currentItem() is not None:
                txt = self.listWidgetNodes.currentItem().text()
                # first item is the position (as string)
                txt = txt[0:txt.find(",")]
                index = int(txt)
                for key, value in self.item_index.items():
                    if value == index:
                        ip = key
                f.write("".join([ip , "\n"]))
            else:
                hf.show_popup_warning("No item selected, please select a host.\nNo item selected!")
                return
        else:
            for ip in self.node_dict_gui:
                f.write("".join([ip , "\n"]))
        f.close()

    def IpNetInfoThread(self):
        # create ips_START_TIME.txt
        ip_file_name = "".join(["IPRadar2/Output/ips_" , configuration.START_TIME , ".txt"])
        f = open(ip_file_name, "w", encoding="utf-8")
        if self.rbSelectedIpInfos.isChecked():
            # default value
            ip = configuration.PUBLIC_IP
            if self.listWidgetNodes.currentItem() is not None:
                txt = self.listWidgetNodes.currentItem().text()
                # first item is the position (as string)
                txt = txt[0:txt.find(",")]
                index = int(txt)
                for key, value in self.item_index.items():
                    if value == index:
                        ip = key
                f.write("".join([ip , "\n"]))
            else:
                hf.show_popup_warning("No item selected, please select a host.\nNo item selected!")
                return
        else:
            for ip in self.node_dict_gui:
                f.write("".join([ip , "\n"]))
        f.close()
        # open ips.txt
        if os.path.isfile(ip_file_name):
            subprocess.call([configuration.TEXT_EDITOR, ip_file_name])

    @pyqtSlot()
    def on_rbAllIpInfos_clicked(self):
        return

    @pyqtSlot()
    def on_rbSelectedIpInfos_clicked(self):
        return
