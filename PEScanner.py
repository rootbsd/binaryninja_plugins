import os, sys, time, datetime
import pefile, magic, hashlib
import string, re, json
import collections
import yara
from virus_total_apis import PublicApi as VirusTotalPublicApi
from PySide import QtGui, QtCore
try:
  import binaryninja
except ImportError:
  sys.path.append('C:\Program Files\Vector35\BinaryNinja\Python')
  import binaryninja
  
API_KEY = 'Your_API_key'
temp = "C:\\Windows\\temp\\binaryninja"
yara_path = "c:\\Yara"

  
class ShowData(QtGui.QTabWidget):
  def __init__(self, pescanner):
    super(ShowData, self).__init__()
    self.pescanner = pescanner
    self.vtEdit = QtGui.QTextEdit()
    self.yaraPath = QtGui.QLineEdit()
    self.yaraPath.setText(yara_path)
    self.yaraEdit = QtGui.QTextEdit()
    self.yaraEdit.setLineWrapMode(QtGui.QTextEdit.NoWrap)
    self.initUI()
    
  def vt(self):
    vt = VirusTotalPublicApi(API_KEY)
    response =  vt.get_file_report(self.pescanner.get_hashes()[0])
    page = ""
    if 'results' in response:
      if response['results']['response_code'] == 1:
        page = page + "Quota: "+str(response['results']['positives'])+"/"+str(response['results']['total'])+"\n\n"
        for AV in response['results']['scans']:
          page = page + AV + ":\t\t" + str(response['results']['scans'][AV]['result']) + "\n"
      else:
        page = "Sample not on VT..."
    self.vtEdit.setText(page)
    
  def yara(self):
    path = self.yaraPath.text()
    print "Yara: "+path
    namespaces = {}
    try:
      for i in os.listdir(path):
        p = os.path.join(path, i)
        if os.path.isfile(p):
          filename , extension = os.path.splitext(p)
          namespaces[filename]=p
      try:
        rules = yara.compile(filepaths=namespaces)
        matches = rules.match(data=self.pescanner.data)
        if not matches:
          self.yaraEdit.setText("No match")
        else:
          s=""
          for j in matches:
            t = ""
            for k in j.strings:
              t=t+str(hex(self.pescanner.bv.start+k[0])).replace("L","")+" "
            s=s+j.namespace+" \t "+j.rule+" "+t+"\n"
          self.yaraEdit.setText(s)
      except Exception as e:
        print(e)
    except:
      self.yaraEdit.setText("Error...")
      
  def quit(self):
    QtCore.QCoreApplication.instance().quit()
    
  def initUI(self):
    md5 = QtGui.QLabel('MD5')
    sha1 = QtGui.QLabel('SHA1')
    sha256 = QtGui.QLabel('SHA256')
    size = QtGui.QLabel('size')
    filetype = QtGui.QLabel('File type')
    filearch = QtGui.QLabel('Architecture')
    imphash = QtGui.QLabel('Imphash')
    timestamp = QtGui.QLabel('Compilation date')
    language = QtGui.QLabel('Language')
    crc = QtGui.QLabel('CRC (actual/claimed)')
    ep = QtGui.QLabel('Entry point')
    verifinfo = QtGui.QLabel('Information')
	
    md5Edit = QtGui.QLineEdit()
    md5Edit.setReadOnly(True)
    md5Edit.setText(self.pescanner.get_hashes()[0])

    sha1Edit = QtGui.QLineEdit()
    sha1Edit.setReadOnly(True)
    sha1Edit.setText(self.pescanner.get_hashes()[1])		
    
    sha256Edit = QtGui.QLineEdit()
    sha256Edit.setReadOnly(True)
    sha256Edit.setText(self.pescanner.get_hashes()[2])
	
    sizeEdit = QtGui.QLineEdit()
    sizeEdit.setReadOnly(True)
    sizeEdit.setText(str(self.pescanner.get_size()))

    filetypeEdit = QtGui.QLineEdit()
    filetypeEdit.setReadOnly(True)
    filetypeEdit.setText(self.pescanner.get_filetype())
    
    imphashEdit = QtGui.QLineEdit()
    imphashEdit.setReadOnly(True)
    imphashEdit.setText(self.pescanner.get_imphash())
    
    (ts, he) = self.pescanner.get_timestamp()
    timestampEdit = QtGui.QLineEdit()
    timestampEdit.setReadOnly(True)
    timestampEdit.setText(ts+" ("+str(hex(he))+")")
    
    languageEdit = QtGui.QLineEdit()
    languageEdit.setReadOnly(True)
    languageEdit.setText(self.pescanner.get_lang())
    
    (crcA, crcC) = self.pescanner.get_CRC()
    crcEdit = QtGui.QLineEdit()
    crcEdit.setReadOnly(True)
    crcEdit.setText(str(hex(crcA)).replace("L", "")+" / "+str(hex(crcA)).replace("L", ""))
    
    (a, b, c, d, e) = self.pescanner.get_entrypoint()
    epEdit = QtGui.QLineEdit()
    epEdit.setReadOnly(True)
    epEdit.setText(str(a)+" "+b+" "+str(c)+" "+str(d)+" "+e+" (bv: "+str(hex(self.pescanner.bv.entry_point)).replace("L","")+")")
	
    verifinfoEdit = QtGui.QTextEdit()
    verifinfoEdit.setReadOnly(True)
    s = ""
    for i in self.pescanner.get_verinfo():
      s = s+i[0]+": "+i[1]+"\n"
    verifinfoEdit.setText(s)
  
    quitButton = QtGui.QPushButton("Quit")
    quitButton.clicked.connect(self.quit)
    
    ExportsEdit = QtGui.QTextEdit()
    ExportsEdit.setReadOnly(True)
    s = ""
    for i in self.pescanner.get_exports():
      s = s+i[0]+":\t"+i[1]+"\n"
    if s == "":
      s = "No export"
    ExportsEdit.setText(s)
    
    ImportsEdit = QtGui.QTextEdit()
    ImportsEdit.setReadOnly(True)
    s = ""
    for i in self.pescanner.get_imports():
      s = s+i[0]
      for j in i[1]:
        s=s+"\n\t"+j[0]+": "+j[1]
      s = s+"\n"
    ImportsEdit.setText(s)
    
    sections = QtGui.QLabel('Sections (Name\t\tVirtAddr\t\tVirtSize\t\tRawSize\t\tMD5\t\tEntropy)')
    SectionsEdit = QtGui.QTextEdit()
    SectionsEdit.setReadOnly(True)
    s=""
    for i in self.pescanner.get_sections():
      s=s+" "+ i[0]+"\t"+str(i[1])+"\t"+str(i[2])+"\t"+str(i[3])+"\t"+i[4]+"\t"+str(i[5])+"\t"+i[6]+"\n"
    SectionsEdit.setText(s)
    
    ressources = QtGui.QLabel("Ressources")
    RessourcesEdit = QtGui.QTextEdit()
    RessourcesEdit.setReadOnly(True)
    s=""
    for i in self.pescanner.get_ressources():
      s=s+i[0]+":\t"+str(i[1])+"\n"
    RessourcesEdit.setText(s)
    
    alertEdit = QtGui.QTextEdit()
    alertEdit.setReadOnly(True)
    alertEdit.setText('\n'.join(self.pescanner.get_alertAPI()))
    
    vtButton = QtGui.QPushButton("VT scan (no submission)")
    self.connect(vtButton, QtCore.SIGNAL("clicked()"), self.vt)
    self.vtEdit.setReadOnly(True)
    self.vtEdit.setText("Click to perform the query")
    
    yaraLabel = QtGui.QLabel("Yara rule directory")
    yaraButton = QtGui.QPushButton("start Yara analysis")
    self.connect(yaraButton, QtCore.SIGNAL("clicked()"), self.yara)
    self.yaraEdit.setReadOnly(True)
    self.yaraEdit.setText("Click to perform an analysis")
    
    tab1 = QtGui.QWidget()	
    tab2 = QtGui.QWidget()
    tab3 = QtGui.QWidget()
    tab4 = QtGui.QWidget()
    tab5 = QtGui.QWidget()
    tab6 = QtGui.QWidget()
    tab7 = QtGui.QWidget()
		
    info_grid = QtGui.QGridLayout()
    
    info_grid.setSpacing(10)
    info_grid.addWidget(md5, 0, 0)
    info_grid.addWidget(sha1, 1, 0)
    info_grid.addWidget(sha256, 2, 0)
    info_grid.addWidget(size, 3, 0)
    info_grid.addWidget(filetype, 4, 0)
    info_grid.addWidget(imphash, 5, 0)
    info_grid.addWidget(timestamp, 6, 0)
    info_grid.addWidget(language, 7, 0)
    info_grid.addWidget(crc, 8, 0)
    info_grid.addWidget(ep, 9, 0)
    info_grid.addWidget(verifinfo, 10, 0)

    info_grid.addWidget(md5Edit, 0, 1)
    info_grid.addWidget(sha1Edit, 1, 1)
    info_grid.addWidget(sha256Edit, 2, 1)
    info_grid.addWidget(sizeEdit, 3, 1)
    info_grid.addWidget(filetypeEdit, 4, 1)
    info_grid.addWidget(imphashEdit, 5, 1)
    info_grid.addWidget(timestampEdit, 6, 1)
    info_grid.addWidget(languageEdit, 7, 1)
    info_grid.addWidget(crcEdit, 8, 1)
    info_grid.addWidget(epEdit, 9, 1)
    info_grid.addWidget(verifinfoEdit, 10, 1)
	
    info_grid.addWidget(quitButton, 11, 1)
    
    export_grid = QtGui.QGridLayout()
    export_grid.setSpacing(10)
    export_grid.addWidget(ExportsEdit, 0, 0)
    
    import_grid = QtGui.QGridLayout()
    import_grid.setSpacing(10)
    import_grid.addWidget(ImportsEdit, 0, 0)
    
    section_grid = QtGui.QGridLayout()
    section_grid.setSpacing(10)
    section_grid.addWidget(sections, 0, 0)
    section_grid.addWidget(SectionsEdit, 1, 0)
    section_grid.addWidget(ressources, 2, 0)
    section_grid.addWidget(RessourcesEdit, 3, 0)
    
    alert_grid = QtGui.QGridLayout()
    alert_grid.setSpacing(10)
    alert_grid.addWidget(alertEdit, 0, 0)
    
    vt_grid = QtGui.QGridLayout()
    vt_grid.setSpacing(10)
    vt_grid.addWidget(vtButton, 0, 0)
    vt_grid.addWidget(self.vtEdit, 1, 0)
    
    yara_grid=QtGui.QGridLayout()
    yara_grid.setSpacing(10)
    yara_grid.addWidget(yaraLabel, 0, 0)
    yara_grid.addWidget(self.yaraPath, 0, 1)
    yara_grid.addWidget(yaraButton, 1, 1)
    yara_grid.addWidget(self.yaraEdit, 2, 1)
    
    tab1.setLayout(info_grid) 
    tab2.setLayout(import_grid)
    tab3.setLayout(export_grid)
    tab4.setLayout(section_grid)
    tab5.setLayout(alert_grid)
    tab6.setLayout(vt_grid)
    tab7.setLayout(yara_grid)
    
    self.addTab(tab1,"Information")
    self.addTab(tab2,"Imports")
    self.addTab(tab3,"Exports")
    self.addTab(tab4,"Sections")
    self.addTab(tab5,"Alert API")
    self.addTab(tab6,"VT")
    self.addTab(tab7,"Yara")
    
    self.resize(1100,650)
    self.setWindowTitle("PE Scanner")    
    
    frameGm = self.frameGeometry()
    screen = QtGui.QApplication.desktop().screenNumber(QtGui.QApplication.desktop().cursor().pos())
    centerPoint = QtGui.QApplication.desktop().screenGeometry(screen).center()
    frameGm.moveCenter(centerPoint)
    self.move(frameGm.topLeft())
    self.show()
		
class PEScanner:
  def __init__(self, data, bv):
    self.bv = bv
    self.data = data
    self.status = False
    self.good_ep_sections = ['.text', '.code', 'CODE', 'INIT', 'PAGE']
    self.alerts_api = ['accept', 'AddCredentials', 'bind', 'CertDeleteCertificateFromStore', 'CheckRemoteDebuggerPresent', 'closesocket', 'connect', 'ConnectNamedPipe', 'CopyFile', 'CreateFile', 'CreateProcess', 'CreateToolhelp32Snapshot', 'CreateFileMapping', 'CreateRemoteThread', 'CreateDirectory', 'CreateService', 'CreateThread', 'CryptEncrypt', 'DeleteFile', 'DeviceIoControl', 'DisconnectNamedPipe', 'DNSQuery', 'EnumProcesses', 'ExitThread', 'FindWindow', 'FindResource', 'FindFirstFile', 'FindNextFile', 'FltRegisterFilter', 'FtpGetFile', 'FtpOpenFile', 'GetCommandLine', 'GetThreadContext', 'GetDriveType', 'GetFileSize', 'GetFileAttributes', 'GetHostByAddr', 'GetHostByName', 'GetHostName', 'GetModuleHandle', 'GetProcAddress', 'GetTempFileName', 'GetTempPath', 'GetTickCount', 'GetUpdateRect', 'GetUpdateRgn', 'GetUserNameA', 'GetUrlCacheEntryInfo', 'GetComputerName', 'GetVersionEx', 'GetModuleFileName', 'GetStartupInfo', 'GetWindowThreadProcessId', 'HttpSendRequest', 'HttpQueryInfo', 'IcmpSendEcho', 'IsDebuggerPresent', 'InternetCloseHandle', 'InternetConnect', 'InternetCrackUrl', 'InternetQueryDataAvailable', 'InternetGetConnectedState', 'InternetOpen', 'InternetQueryDataAvailable', 'InternetQueryOption', 'InternetReadFile', 'InternetWriteFile', 'LdrLoadDll', 'LoadLibrary', 'LoadLibraryA', 'LockResource', 'listen', 'MapViewOfFile', 'OutputDebugString', 'OpenFileMapping', 'OpenProcess', 'Process32First', 'Process32Next', 'recv', 'ReadProcessMemory', 'RegCloseKey', 'RegCreateKey', 'RegDeleteKey', 'RegDeleteValue', 'RegEnumKey', 'RegOpenKey', 'send', 'sendto', 'SetKeyboardState', 'SetWindowsHook', 'ShellExecute', 'Sleep', 'socket', 'StartService', 'TerminateProcess', 'UnhandledExceptionFilter', 'URLDownload', 'VirtualAlloc', 'VirtualProtect', 'VirtualAllocEx', 'WinExec', 'WriteProcessMemory', 'WriteFile', 'WSASend', 'WSASocket', 'WSAStartup', 'ZwQueryInformation']
    self.alerts_imp = ['ntoskrnl.exe', 'hal.dll', 'ndis.sys']
    self.mgc_path="c:\\Windows\\System32\\magic.mgc"

    try:
      self.pe = pefile.PE(data=data, fast_load=True)
      self.pe.parse_data_directories( directories=[ 
      pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
      pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
      pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS'],
      pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
      self.status = True
    except:
      print("Cannot parse the file (maybe not PE?)")
      
  def convert_char(self, char):
    if char in string.ascii_letters or \
      char in string.digits or \
      char in string.punctuation or \
      char in string.whitespace:
      return char
    else:
      return r'\x%02x' % ord(char)

  def convert_to_printable(self, s):
    return ''.join([self.convert_char(c) for c in s])
	
  def get_filetype(self, data=None):
    """There are two versions of python-magic floating around, and annoyingly, the interface 
    changed between versions, so we try one method and if it fails, then we try the other.
    NOTE: you may need to alter the magic_file for your system to point to the magic file."""
    if data == None:
      data=self.data
    if sys.modules.has_key('magic'):
      try:
        ms = magic.open(magic.MAGIC_NONE) 
        ms.load() 
        return ms.buffer(data)
      except:
        try:
          return magic.from_buffer(data)
        except magic.MagicException:
          try:
            magic_custom = magic.Magic(magic_file=self.mgc_path)
            return magic_custom.from_buffer(data)
          except:
            return ''
    return ''
	
  def check_ep_section(self, pe):
    """ Determine if a PE's entry point is suspicious """
    name = ''
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    pos = 0
    for sec in pe.sections:
      if (ep >= sec.VirtualAddress) and \
        (ep < (sec.VirtualAddress + sec.Misc_VirtualSize)):
        name = sec.Name.replace('\x00', '')
        break
      else: 
        pos += 1
    return (ep, name, pos)
	
  def check_rsrc(self):
    ret = {}
    if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
      i = 0
      for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if resource_type.name is not None:
          name = "%s" % resource_type.name
        else:
          name = "%s" % pefile.RESOURCE_TYPE.get(resource_type.struct.Id)
        if name == None:
          name = "%d" % resource_type.struct.Id
        if hasattr(resource_type, 'directory'):
          for resource_id in resource_type.directory.entries:
            if hasattr(resource_id, 'directory'):
              for resource_lang in resource_id.directory.entries:
                data = self.pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                filetype = self.get_filetype(data)
                lang = pefile.LANG.get(resource_lang.data.lang, '*unknown*')
                sublang = pefile.get_sublang_name_for_lang( resource_lang.data.lang, resource_lang.data.sublang )
                ret[i] = (name, resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size, filetype, lang, sublang)
                i += 1
    return ret  
   
  def get_lang(self):
    resources = self.check_rsrc()
    ret = []
    lang_holder = []
    for rsrc in resources.keys():
      (name,rva,size,type,lang,sublang) = resources[rsrc]
      lang_holder.append(lang)
      lang_count = collections.Counter(lang_holder)
      lang_common = lang_count.most_common(1)
      for lang_likely,occur in lang_common:
        ret = lang_likely.split('_')[1]
    return ret

  def get_timestamp(self):
    IMAGE_FILE_HEADER=self.bv.read(self.bv.start+0x3c, 0x4)
    IMAGE_FILE_HEADER=int(IMAGE_FILE_HEADER[::-1].encode("hex"), 16)
    COMPILATION_DATE=self.bv.read(self.bv.start+IMAGE_FILE_HEADER+0x8, 0x4)
    COMPILATION_DATE=int(COMPILATION_DATE[::-1].encode("hex"), 16)
    return(    datetime.datetime.fromtimestamp(
               int(COMPILATION_DATE)
               ).strftime('%Y-%m-%d %H:%M:%S'), COMPILATION_DATE
    )
	
  def get_imphash(self):
    return self.pe.get_imphash()	

  def get_size(self):
    return len(self.data)
    
  def get_filearch(self):
    IMAGE_FILE_HEADER=self.bv.read(self.bv.start+0x3c, 0x4)
    IMAGE_FILE_HEADER=int(IMAGE_FILE_HEADER[::-1].encode("hex"), 16)
    Machine=self.bv.read(self.bv.start+IMAGE_FILE_HEADER+0x4, 0x2)
    Machine=int(Machine[::-1].encode("hex"), 16)
    
    if Machine == 0x14C:
      return "32 Bits binary"
    elif Machine == 0x8664:
      return "64 bits binary"
    else:
      return ''
	  
  def get_hashes(self):
    return hashlib.md5(self.data).hexdigest(), hashlib.sha1(self.data).hexdigest(), hashlib.sha256(self.data).hexdigest()
	  
  def get_CRC(self):
    crc_claimed = self.pe.OPTIONAL_HEADER.CheckSum
    crc_actual  = self.pe.generate_checksum()
    return crc_actual, crc_claimed
	  
  def get_entrypoint(self):
    s = ''
    (ep, name, pos) = self.check_ep_section(self.pe)
    ep_ava = ep+self.pe.OPTIONAL_HEADER.ImageBase
    if (name not in self.good_ep_sections) or pos == len(self.pe.sections):
      s = "[SUSPICIOUS]"
    return hex(ep_ava), name, pos, len(self.pe.sections), s

  def get_verinfo(self):
    """ Determine the version info in a PE file """
    ret = []
        
    if hasattr(self.pe, 'VS_VERSIONINFO'):
      if hasattr(self.pe, 'FileInfo'):
        for entry in self.pe.FileInfo:
          if hasattr(entry, 'StringTable'):
            for st_entry in entry.StringTable:
              for str_entry in st_entry.entries.items():
                # yes... it annoyed me that much .. ocd whatttt
                if 'OriginalFilename' in str_entry:
                  p = self.convert_to_printable(str_entry[0]), self.convert_to_printable(str_entry[1])
                  ret.append(p)
                else:
                  p = self.convert_to_printable(str_entry[0]), self.convert_to_printable(str_entry[1])
                  ret.append(p)
          elif hasattr(entry, 'Var'):
            for var_entry in entry.Var:
              if hasattr(var_entry, 'entry'):
                p = self.convert_to_printable(var_entry.entry.keys()[0]), var_entry.entry.values()[0]
                ret.append(p)
    return ret
	
  def get_sections(self):
    out = []
    for sec in self.pe.sections:
      s = []
      s.append(''.join([c for c in sec.Name if c in string.printable]))
      s.append(hex(sec.VirtualAddress)) 
      s.append(hex(sec.Misc_VirtualSize)) 
      s.append(hex(sec.SizeOfRawData))
      s.append(sec.get_hash_md5())
      s.append(sec.get_entropy())
	  
      if sec.SizeOfRawData == 0 or (sec.get_entropy() > 0 and sec.get_entropy() < 1) or sec.get_entropy() > 7:
        s.append("[SUSPICIOUS]")
      else:
        s.append("")
      out.append(s)
    return out
	
  def get_ressources(self):
    out = []
    resources = self.check_rsrc()
    if len(resources):
      names_holder = []
      for rsrc in resources.keys():
        (name,rva,size,type,lang,sublang) = resources[rsrc]
        names_holder.append(name)
        names_count = collections.Counter(names_holder)
        names_common = names_count.most_common()
      for name,occur in names_common:
        i=[]
        i.append(name)
        i.append(occur)
        out.append(i)
    return out
	
  def get_imports(self):
    out = []
    imports_total = len(self.pe.DIRECTORY_ENTRY_IMPORT)
    if imports_total > 0:
      for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
        #entry.dll
        p=[]
        for imp in entry.imports:
          if (imp.name != None) and (imp.name != ""):
            d = hex(imp.address), imp.name
          p.append(d)
        c = entry.dll, p
        out.append(c)
    return out
	
  def check_imports(self):
    ret = []
    if not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
      return ret
    for lib in self.pe.DIRECTORY_ENTRY_IMPORT:
      for entry in self.alerts_imp:
        if re.search(lib.dll, entry, re.I):
          ret.append(lib.dll)
      for imp in lib.imports:
        if (imp.name != None) and (imp.name != ""):
          for alert in self.alerts_api:
            if imp.name.startswith(alert):
              ret.append(imp.name)
    return ret
	
  def get_alertAPI(self):
    out = []
    imports = self.check_imports()
    if len(imports):
      ret = []
      for imp in imports:
        ret.append(imp)
      for i in sorted(set(ret)):
        out.append(i)
    return out
	
  def get_exports(self):
    out = []
    if hasattr(self.pe,"DIRECTORY_ENTRY_EXPORT"):
      for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
        j = (hex(self.bv.start+exp.address).replace("L", ""),exp.name)
        out.append(j)
    return out

def pestart(bv, addr, lentgh):
  bv.save(temp)
  data=""
  try:
    FILE = open(temp, "rb")
    data = FILE.read()
    FILE.close()
  except:
    print("Cannot read the file...")
  os.remove(temp)
  if data != "":
    pescan = PEScanner(data, bv)
    if pescan.status == True:
      ex = ShowData(pescan)
      app.exec_()
    print "End"


try:
  app = QtGui.QApplication([])
except:
  app = QtGui.QApplication.instance()
binaryninja.PluginCommand.register_for_range("Get PE information", "Get PE information.", pestart)
