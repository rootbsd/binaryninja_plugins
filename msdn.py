from PySide import QtGui, QtCore, QtWebKit
import re, urllib2

try:
  import binaryninja
except ImportError:
  sys.path.append('C:\Program Files\Vector35\BinaryNinja\Python')
  import binaryninja

class ShowWeb(QtGui.QWidget):
  def __init__(self, url):
    super(ShowWeb, self).__init__()
    self.url = url
    self.initUI()
    
  def initUI(self):
    if self.url == "":
      content = QtGui.QLabel("Error, no documentation found...")
      layout = QtGui.QVBoxLayout()
    else:
      content = QtWebKit.QWebView()
      content.setUrl(self.url)
      layout = QtGui.QVBoxLayout()
    layout.addWidget(content)
    self.setLayout(layout)
    self.resize(1100,650)
    self.setWindowTitle("MSDN documentation")    
    frameGm = self.frameGeometry()
    screen = QtGui.QApplication.desktop().screenNumber(QtGui.QApplication.desktop().cursor().pos())
    centerPoint = QtGui.QApplication.desktop().screenGeometry(screen).center()
    frameGm.moveCenter(centerPoint)
    self.move(frameGm.topLeft())
    self.show()

def msdn(bv, addr, lentgh):
  asm = bv.get_disassembly(addr)
  hexapattern = r'(0x[0-9a-fA-F]+)(?:--)?'
  m = re.findall(hexapattern, asm)
  if len(m) == 1:
    symbol_addr = m[0]
    s = bv.get_symbol_at(int(symbol_addr, 16))
    if s:
      pattern = r'!(\w+)@'
      n = re.findall(pattern, s.name)
      if n:
        web = urllib2.urlopen("https://social.msdn.microsoft.com/search/en-US/feed?format=RSS&query="+n[0]).read()
        urls = re.findall('https://"?\'?([^"\'>]*).aspx', web)
        if len(urls) >= 2:
          url = "https://"+urls[0]+".aspx"
        else:
          url = ""
      else:
        url = ""
    else:
      url = ""
  else:
    url = ""
  ex = ShowWeb(url)
  app.exec_()

try:
  app = QtGui.QApplication([])
except:
  app = QtGui.QApplication.instance()
binaryninja.PluginCommand.register_for_range("Get MSDN information", "Get MSDN information.", msdn)