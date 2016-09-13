# binaryninja_plugins
This repository contains Binary Ninja plugins. Binary Ninja is a reverse engineering platform, more information: https://binary.ninja/

## PE Scanner
This plugin shows an additional QT GUI with additional information concerning the analysed PE.

List of information:
  * PE information (hashes, compilaiton date, metadata...)
  * IAT
  * EAT
  * Sections
  * alert API (list of suspicious API)
  * VirusTotal quota
  * Yara rules support

The code is initially based on pescanner.py available there: https://github.com/hiddenillusion/AnalyzePE/blob/master/pescanner.py
The code was tested on Windows platforms.

Requierements
  * pefile
  * magic (for x64: https://github.com/pidydx/libmagicwin64)
  * yara
  * virus_total_apis
  * pyside
  * json
  * re
The best way to have all the dependencies is to use pip on a standalone python 2.7 install and copy the site-packages directory to the Binary Ninja install path.

TODO:
  * do not use pefile but only Binary Ninja API
  * do not create a temporary file

Few screenshots:
![Capture 1](/images/Capture1.png)
![Capture 2](/images/Capture2.png)
![Capture 1](/images/Capture1.png)
![Capture 3](/images/Capture3.png)
![Capture 4](/images/Capture4.png)
![Capture 5](/images/Capture5.png)
![Capture 6](/images/Capture6.png)
![Capture 7](/images/Capture7.png)

