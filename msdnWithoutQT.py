import re, urllib2, os

try:
  import binaryninja
except ImportError:
  sys.path.append('C:\Program Files\Vector35\BinaryNinja\Python')
  import binaryninja

class ShowWeb():
  def __init__(self, url):
    self.url = url
    
  def Browser(self):
    if self.url == "":
      print("Error, no documentation found...")
    else:
      print("URL :"+self.url)
      os.system('start %s' % self.url)

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
  ex.Browser()

binaryninja.PluginCommand.register_for_range("Get MSDN information (no QT)", "Get MSDN information (no QT).", msdn)
