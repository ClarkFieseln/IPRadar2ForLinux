import sys
if "IPRadar2" in str(sys.argv):
    import configuration
else:
    from IPRadar2 import configuration
import pickle
from PyQt5.QtWidgets import QMessageBox
import PyQt5.QtCore as QtCore
import logging
from collections import namedtuple
from playsound import playsound
import threading



Question = namedtuple('Question', ['ip','infos'])

def show_popup_warning(text):
    msg = QMessageBox()
    msg.setWindowTitle("Warning!")
    msg.setIcon(QMessageBox.Warning)
    msg.setText(text)
    msg.setWindowFlags(msg.windowFlags() | QtCore.Qt.WindowStaysOnTopHint);
    msg.exec_()

def show_popup_error(text):
    msg = QMessageBox()
    msg.setWindowTitle("Error!")
    msg.setIcon(QMessageBox.Critical)
    msg.setText(text)
    msg.setWindowFlags(msg.windowFlags() | QtCore.Qt.WindowStaysOnTopHint);
    msg.exec_()

def show_popup_information(text):
    msg = QMessageBox()
    msg.setWindowTitle("Information")
    msg.setIcon(QMessageBox.Information)
    msg.setText(text)
    msg.setWindowFlags(msg.windowFlags() | QtCore.Qt.WindowStaysOnTopHint);
    msg.exec_()

def show_popup_question(text):
    msg = QMessageBox()
    msg.setWindowTitle("Question")
    msg.setIcon(QMessageBox.Question)
    msg.setText(text)
    msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel)
    msg.setWindowFlags(msg.windowFlags() | QtCore.Qt.WindowStaysOnTopHint);
    return msg.exec_()

def save_obj(obj, name):
    with open("".join(['obj/' , name , '.pkl']), 'wb') as f:
        pickle.dump(obj, f, pickle.HIGHEST_PROTOCOL)

def load_obj(name):
    with open("".join(['obj/' , name , '.pkl']), 'rb') as f:
        return pickle.load(f)

# find 2nd occurrence of char/string within a string
def find_2nd(string, substring):
   return string.find(substring, string.find(substring) + 1)

# log information of packet
def log_info_layer(packet):
   try:
      if packet.ip:
         if configuration.PACKED_OUTPUT == False:
             info = "".join(["{0:5}".format(packet.highest_layer) , ": {0:16}".format(packet.ip.src) , "-> {0:16}".format(packet.ip.dst)])
         else:
             info = "".join([packet.highest_layer , ": " , packet.ip.src , " -> " , packet.ip.dst])
         logging.info(info)
   except AttributeError:
      logging.exception("AttributeError")
   except Exception: # avoid catching exceptions like SystemExit, KeyboardInterrupt, etc.
      return

# log information of geolocations
def log_geolocations(response_src, response_dst, host_src_arg, host_dst_arg):
   try:
      response_src.country = str(response_src.country)
      response_src.city = str(response_src.city)
      response_dst.country = str(response_dst.country)
      response_dst.city = str(response_dst.city)
      host_src_arg = str(host_src_arg)
      host_dst_arg = str(host_dst_arg)
      # log locations
      if configuration.PACKED_OUTPUT == False:
          log_location = "".join(["(" , response_src.country , ", {0:32}".format(response_src.city) , ", {0:38}".format(host_src_arg) , " -> " , \
                  response_dst.country , ", {0:32}".format(response_dst.city) , ", {0:38}".format(host_dst_arg) , ")"])
      else:
          log_location = "".join(["(" , response_src.country , "," , response_src.city , "," , host_src_arg , " -> " , \
                   response_dst.country , "," , response_dst.city , "," , host_dst_arg , ")"])
      logging.info(log_location)
   except AttributeError:
      logging.exception("AttributeError")
   except Exception as e: # avoid catching exceptions like SystemExit, KeyboardInterrupt, etc.
      logging.exception("Exception " + str(e))
      return

def thread_sound(sound_file):
    playsound(sound_file)

def playsound_block_false(sound_file):
    t = threading.Thread(target=thread_sound, args=(sound_file,))
    t.start()
