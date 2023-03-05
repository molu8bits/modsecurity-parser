#!/bin/bash

# molu8bits(at) gmail [dot] com
# 2019.01

PARAMS=""

if [[ -z "$F" ]]; then F=/opt/mounted/modsec_audit.log; PARAMS=${PARAMS}" -f $F"; else PARAMS=${PARAMS}" -f /opt/mounted/${F}"; fi;

if [[ ! -z "$J" ]]; then PARAMS=${PARAMS}" -j $J"; fi;
if [[ ! -z "$X" ]]; then PARAMS=${PARAMS}" -x $X"; fi;
if [[ ! -z "$G" ]]; then PARAMS=${PARAMS}" -g $G"; fi;
if [[ ! -z "$EXCLUDE" ]]; then PARAMS=${PARAMS}" -e $EXCLUDE"; fi;
if [[ ! -z "$INCLUDE" ]]; then PARAMS=${PARAMS}" -i $INCLUDE"; fi;
if [[ ! -z "$L" ]]; then PARAMS=${PARAMS}" -l $L"; fi;
if [[ ! -z "$JSONONEPERLINE" ]]; then PARAMS=${PARAMS}" --jsononeperline"; fi;
if [[ ! -z "$VERSION3" ]]; then PARAMS=${PARAMS}" --version3"; fi;
if [[ ! -z "$JSONAUDIT" ]]; then PARAMS=${PARAMS}" --jsonaudit"; fi;

if [[ ! -z "$HELP" ]]; then
   echo "Help menu - docker additional parameters to pass"
   echo "  F={filename} - modsec audit log to parse, modsec_audit.log by default"
   echo "  J={filename} - JSON output filename"
   echo "  X={filename} - Excel report output filename"
   echo "  G={filename} - Charts output filename"
   echo "  E={filename} - IP addresses to exclude (space separated, enclosed by parenthesis)"
   echo "  I={filename} - IP addresses to include (space separated, encolsed by paranthesis)"
   echo "  L={filename} - Log from operation filename"
   echo "  JSONONEPERLINE=Yes - json output log format"
   echo "  VERSION3=Yes         - to parse Modsecurity3 audit logs"
   echo "  JSONAUDIT=Yes        - to parse JSON type of Modsecurity2/3 logs"
else
   /usr/bin/python3 /opt/mparser/modsecurity_parser.py $PARAMS
fi
