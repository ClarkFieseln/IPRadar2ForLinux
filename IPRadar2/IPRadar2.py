import sys
if "IPRadar2" in str(sys.argv):
    print("Running in an IDE")
    import init_app
    import configuration
else:
    print("Running as an executable")
    from IPRadar2 import init_app
    from IPRadar2 import configuration

# IMPORTANT: initConfig() must be called at the very beginning
init_app.initConfig()

from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QFont
import sys
import logging
if "IPRadar2" in str(sys.argv):
    from mainAppWindow import MyMainWindow
else:
    from IPRadar2.mainAppWindow import MyMainWindow



def main():
    logging.info("entering main()..")
    app = QApplication(sys.argv)
    font = QFont()
    font.setPointSize(configuration.FONT_SIZE)
    app.setFont(font)
    ui = MyMainWindow()
    ui.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
