# modsecurity audit log parser, analyser and chart maker

![CI](https://github.com/molu8bits/modsecurity-parser/workflows/CI/badge.svg?branch=develop&event=push)
[![codecov](https://codecov.io/gh/molu8bits/modsecurity-parser/branch/master/graph/badge.svg?token=BY0D5SNBR8)](https://codecov.io/gh/molu8bits/modsecurity-parser)
![Docker Image Size](https://img.shields.io/docker/image-size/molu8bits/modsecurity-parser.svg?sort=date)
![Docker Image Version (latest by date):](https://img.shields.io/docker/v/molu8bits/modsecurity-parser.svg?sort=date)
![Docker Pulls](https://img.shields.io/docker/pulls/molu8bits/modsecurity-parser.svg)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=modsecurity-parser&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=modsecurity-parser)
[![Lines of Code](https://sonarcloud.io/api/project_badges/measure?project=modsecurity-parser&metric=ncloc)](https://sonarcloud.io/summary/new_code?id=modsecurity-parser)

## TL;DR

Get the overview of security incidents reported by modsecurity module from modsec_audit.log file.

## 2023.05.03 update

- fix showruleid #24
- CI github actions
- address vulnerabilities

## 2023.01.01 update

- renamed to modsecurity_parser
- fix for timezone with miliseconds
- linting, testing added
- requirements vulnerabilities fixed

## 2020.09.20 update

- added support for logs from timezone "UTC-..."
- updated plotting to matplotlib.3.1
- added dockerhub autobuild
- added requirements.txt

## 2019.04.17 update

- added support for Modsecurity3 log (Nginx/Apache)
- added feature to read Modsecurity log in JSON format

## Description

modsecurity parser is a python program to read [https://www.modsecurity.org/](https://www.modsecurity.org/)  modsec_audit.log, transform read events into more human and machine readable formats (xlsx/json) and make basic charts.

Functionality list:

- JSON output file with formatting conformed to JSON logging added into Modsecurity 2.9
- XLSX output file which can be analysed further with desktop tools
- PNG file with some basic charts - Timeline nonblocked vs intercepted events, TOP10 IP source address, TOP20 Rule IDs hit, TOP10 Attacks intercepted

## Graph analysis examples

<p align="left">
   <img src="/images/timeline.png" width="950" />
</p>  

<p align="center">

   <img src="/images/top10ipaddresses.png" width="250" />
   <img src="/images/top10intercepted.png" width="250" />
   <img src="/images/top20ruleID.png" width="250" />  
</p>

## Installation

Software needs at least Python 3.8.10 with additional libraries:

- pandas 1.1.3
- Pillow 9.2.0
- matplotlib 3.3.2
- numpy 1.22.4
- openpyxl 2.4.2
  
Install them with command

```bash
pip3 install -r requirements.txt
```

## Basic usage

```bash
python3 modsecurity_parser.py -f /home/user/logs/modsec_audit.log
```

for that case results will be recorded into subdirectory "modsec_output" where the log to analyse is placed.

## More options

```bash
python3 modsecurity_parser.py -h
```

Filters INCLUDE and EXCLUDE are available for IP source addresses.

--exclude option ( e.g. "--exclude 192.168.0.1 10.0.0.1") just skips events with given IP source addresses

--include (e.g. "--include 10.0.5.6") take precedence over EXCLUDE. INCLUDE process only events with given IP source addresses.

--jsononeperline  - option recommended for big number of events where e.g. produced JSON is supposed to be read by other SIEM tool. Uses the very same format as modsecurity software when type of logging is set to "JSON".

Processing Modsecurity3 log

--version3 (e.g. "modsecurity_parser.py -f modsec_audit.log --version3"

Processing Modsecurity log in JSON format:

--jsonaudit (e.g. "modsecurity_parser.py -f modsec_audit.log --jsonaudit"

## Limitations

- The biggest tested modsec_audit.log was 1GB size with around 70000 records. It took more or less 5 minutes on an 8 years old workstation and memory usage temporarily raised to 2GB of RAM
- modsec_audit.log were taken from Apache web servers with locale set to en-US. Software can except some errors if datatime format is different in the audited log. Adjust LOG_TIMESTAMP_FORMAT and LOG_TIMESTAMP_FORMAT_SHORT accordingly
- To process more than 90000 events just adjust MAXEVENTS
- Tested with modsec_audit.log from version 2.8/2.9/3.0. Anyway Modsecurity3 for some cases produces empty H section and not all information is available to be properly presented in all graphs

## run via Docker

Create a subfolder (e.g. "modseclogs") and put into some modsecurity audit logs (by default modsec_audit.log name is processed only).
Output files will be created inside of ${subfolder}/modsec_output

Run command

```bash
docker run --rm -ti --mount type=bind,source="$(pwd)"/modseclogs,target=/opt/mounted molu8bits/modsecurity-parser:latest
```

Get some more docker options:

```bash
docker run --rm -ti -e HELP=Yes molu8bits/modsecurity-parser:latest
```
