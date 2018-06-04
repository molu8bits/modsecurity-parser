# modsecurity audit log parser and analyser

# Description
modsecurity parser is a python program to read <a href="https://www.modsecurity.org/">modsecurity.org</a> modsec_audit.log , tranform read events into more human and machine readable formats (xlsx/json) and make basic analysis presented as graphs.

<p>
Functionality list:
  <li>JSON output file with formatting conformed to JSON logging added into Modsecurity 2.9</li>
  <li>XLSX output file which can be analysed further with desktop tools</li>
  <li>PNG file with some basic analysis - Timeline nonblocked vs intercepted events, TOP10 IP source address, TOP20 Rule IDs hit, TOP10 Attacks intercepted</li>



# Graph analysis examples
<p align="left">
   <img src="/images/timeline.png" width="950" />
</p>
<br>
<p align="center">

   <img src="/images/top10ipaddresses.png" width="250" />
   <img src="/images/top10intercepted.png" width="250" />
   <img src="/images/top20ruleID.png" width="250" />
  <br>
</p>


# xlsx format output example:
<p align="center">
   <img src="/images/xlsx_report_01.png" width="750" />
</p>
<p align="center">
   <img src="/images/xlsx_report_02.png" width="750" />
</p>


# Installation
  Software needs at least Python 3.5.2 with additional libraries:
  <li>Pandas 0.22</li>
  <li>Pillow</li>
  <li>matplotlib 2.1.2 </li>
  <li>numpy 1.13.1</li>
  <li>openpyxl 2.4.0</li> 


  
# Usage
<h4>Simplest usage</h4>

```
python3 modsecurity-parser.py -f /home/user/logs/modsec_audit.log
```

for that case results will be recorded into subdirectory "modsec_output" where the log to analyse is placed.

<h4>more options:</h4>

```
python3 modsecurity-parser.py -h
```

<p>
By default scripts reads only first 90000 of events.

Filters INCLUDE and EXCLUDE are available for IP source addresses.
<p>
INCLUDE ("--exclude 192.168.0.1 10.0.0.1") just skips events with given IP source address
<p>
INCLUDE take precedense over EXLUDE. INCLUDE process only events with given IP source address.

# LIMITATIONS:
<li>The biggest tested modsec_audit.log was around 1GB size with around 70000 records. It took more or less 5 minutes on 8years old workstation and took temporarily around 2GB of RAM.</li>
<li>modsec_audit.log were taken from Apache web servers with locale set to en-US - can except some errors if datatime is different. Adjust LOG_TIMESTAMP_FORMAT and LOG_TIMESTAMP_FORMAT_SHORT accordingly</li>
<li>To process more than 90000 events just adjust MAXEVENTS</li>
<li>Tested with modsec_audit.log from version 2.8/2.9 only. Should work with newest 3.0 and older ones but to be confirmed</li>

# TODO
<li>put the software till 15 June 2018</li>
<li>add example of modsec_audit.log to test - till 15 June 2018 </li>
<li>add sample report files - till 15 June 2018 </li>
<li>create Wiki - till 30 July 2018 </li>
