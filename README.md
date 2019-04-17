# modsecurity audit log parser, analyser and chart maker

# TL;DR
Get the overview of security incidents reported by modsecurity module from modsec_audit.log file.

# 2019.04.17 update
- added support for Modsecurity3 log (Nginx/Apache)
- added feature to read Modsecurity log in JSON format


# Description
modsecurity parser is a python program to read <a href="https://www.modsecurity.org/">modsecurity.org</a> modsec_audit.log , tranform read events into more human and machine readable formats (xlsx/json) and make basic charts.


<p>
Functionality list:
  <li>JSON output file with formatting conformed to JSON logging added into Modsecurity 2.9</li>
  <li>XLSX output file which can be analysed further with desktop tools</li>
  <li>PNG file with some basic charts - Timeline nonblocked vs intercepted events, TOP10 IP source address, TOP20 Rule IDs hit, TOP10 Attacks intercepted</li>



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



# Installation
  Software needs at least Python 3.5.2 with additional libraries:
  <li>Pandas 0.22</li>
  <li>Pillow</li>
  <li>matplotlib 2.1.2 </li>
  <li>numpy 1.13.1</li>
  <li>openpyxl 2.4.0</li> 


  
# Basic usage

```
python3 modsecurity-parser.py -f /home/user/logs/modsec_audit.log
```

for that case results will be recorded into subdirectory "modsec_output" where the log to analyse is placed.


# More options

<p>

```
python3 modsecurity-parser.py -h
```


Filters INCLUDE and EXCLUDE are available for IP source addresses.
<p>
--exclude option ( e.g. "--exclude 192.168.0.1 10.0.0.1") just skips events with given IP source addresses
<p>
--include (e.g. "--include 10.0.5.6") take precedense over EXLUDE. INCLUDE process only events with given IP source addresses.
<p>
--jsononeperline  - option recommended for big number of events where e.g. produced JSON is supposed to be read by other SIEM tool. Uses the very same format as modsecurity software when type of logging is set to "JSON". 


Processing Modsecurity3 log
<p>
--version3 (e.g. "modsecurity-parser.py -f modsec_audit.log --version3"
<p>

Processing Modsecurity log in JSON format:
<p>
--jsonaudit (e.g. "modsecurity-parser.py -f modsec_audit.log --jsonaudit"



# Limitations:
<li>The biggest tested modsec_audit.log was 1GB size with around 70000 records. It took more or less 5 minutes on 8years old workstation and memory usage temporarily raised to 2GB of RAM.</li>
<li>modsec_audit.log were taken from Apache web servers with locale set to en-US. Software can except some errors if datatime format is different in the audited log. Adjust LOG_TIMESTAMP_FORMAT and LOG_TIMESTAMP_FORMAT_SHORT accordingly</li>
<li>To process more than 90000 events just adjust MAXEVENTS</li>
<li>Tested with modsec_audit.log from version 2.8/2.9/3.0. Anyway Modsecurity3 for some cases produces empty sectionH and not all information is available to be properly presented in all graphs</li>

# run via Docker

Create a subfolder (e.g. "modseclogs") and put into some modsecurity audit logs (by default modsec_audit.log name is processed only).
Output files will be created inside of ${subfolder}/modsec_output

Run command

```bash
docker run --rm -ti --mount type=bind,source="$(pwd)"/modseclogs,target=/opt/mounted molu8bits/modsecurity-parser:0.2
```

Get some more docker options:
```bash
docker run --rm -ti -e HELP=Yes molu8bits/modsecurity-parser:0.2
```

TODO
Update Docker image to version 0.2

