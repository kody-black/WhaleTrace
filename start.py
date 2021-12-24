import sys
import time

import dpkt
import pcap
from PyQt5.QtGui import QTextCursor
from PyQt5.QtWidgets import QApplication, QDialog
from scapy.all import *
import select_gui
# list all of the Internet devices
from WhaleTrace import main_start
from getdevs import get_key

devs = get_key('WLAN')


class FirstDialog(QDialog):

    def __init__(self, parent=None):
        super(QDialog, self).__init__(parent)
        self.ui = select_gui.Ui_Dialog()
        self.ui.setupUi(self)
        for i in devs:
            self.ui.devSelect.addItem(i)

    def onUpdateText(self, text):
        """Write console output to text widget."""
        cursor = self.process.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertText(text)
        self.process.setTextCursor(cursor)
        self.process.ensureCursorVisible()

    def beginSniff(self):
        main_start()
        self.close()


if __name__ == "__main__":
    myapp = QApplication(sys.argv)
    myDlg = FirstDialog()
    myDlg.show()
    sys.exit(myapp.exec_())
