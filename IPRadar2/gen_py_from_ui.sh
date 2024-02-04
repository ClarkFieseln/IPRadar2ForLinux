python3 -m PyQt5.uic.pyuic -x mainWindow.ui -o Ui_mainWindow.py
echo "Please replace in UI_mainWindow.py as indicated:"
echo "###################################################"
echo "from CheckableComboBox import CheckableComboBox"
echo "->"
echo "import sys
if "\"IPRadar2\"" in str(sys.argv):
    from CheckableComboBox import CheckableComboBox
else:
    from IPRadar2.CheckableComboBox import CheckableComboBox"
read -n 1 -s -r -p "Press any key to continue"
