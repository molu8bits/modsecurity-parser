"""modsecurity_parser.py.
Module to analyze modsecurity audit log and present output as:
  - json file (compatible with default JSON logging)
  - xlsx report
  - png with graphs
2019.01 - molu8bits (at) gmail (dot) com
"""

from collections import OrderedDict, Counter
from time import localtime, strftime
from datetime import datetime

import os
import sys
import argparse
import re
import json
import openpyxl

import numpy as np
import pandas as pd

import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')


DEBUG = False
MAXEVENTS = 90000
SAVEOUTPUTJSON = True
JSON_ONE_PER_LINE = False
FILTER_INCLUDE = True
FILTER_EXCLUDE = True
LOG_TIMESTAMP_FORMAT = '%d/%b/%Y:%H:%M:%S %z'               # e.g. "01/Mar/2018:05:26:41 +0100"
LOG_TIMESTAMP_FORMAT_SHORT = '%Y-%m-%d_%H:%M'
LOG_TIMESTAMP_FORMAT_TIMEMS = '%d/%b/%Y:%H:%M:%S.%f %z'     # e.g. "01/Mar/2018:05:26:41.341644 +0100"


# modsec_patterns
# a_pattern = re.compile('^--\w{6,10}-A--$')
a_pattern = re.compile(r'^--\w{6,10}-A--$')
# z_pattern = re.compile('^--\w{6,10}-Z--$')
z_pattern = re.compile(r'^--\w{6,10}-Z--$')
modsec_event_types = ['A', 'B', 'C', 'E', 'F', 'H', 'I', 'J', 'K']
MODSEC_MESSAGE_FILE_PATTERN = r'(?<=\[file\s\").*?(?="\])'
MODSEC_MESSAGE_MSG_PATTERN = r'(?<=\[msg\s\").*?(?=\"\])'
MODSEC_MESSAGE_ID_PATTERN = r'(?<=\[id\s\").*?(?=\"\])'
MODSEC_MESSAGE_SEVERITY_PATTERN = r'(?<=\[severity\s\").*?(?=\"\])'
MODSEC_MESSAGE_MATURITY_PATTERN = r'(?<=\[maturity\s\").*?(?=\"\])'
MODSEC_MESSAGE_ACCURACY_PATTERN = r'(?<=\[accuracy\s\").*?(?=\"\])'
MODSEC_MESSAGE_MESSAGE_PATTERN = r'(?<=Message:).*?(?=\.\ \[)'
MODSEC_V3_MESSAGE_PHASE_PATTERN = r'(?<=\(phase).*?(?=\))'
# MODSEC_V3_MESSAGE_PHASE_PATTERN = r'(?:\(phase).*?(?:\))'           # (phase 2)
# MODSEC_V3_MESSAGE_PHASE_PATTERN = r'(?:\(phase).*?(?=\))'
# MODSEC_V3_MESSAGE_MESSAGE_PATTERN = r'(?<=\Message:).*?(?=\[)'
MODSEC_V3_MESSAGE_MESSAGE_PATTERN = r'(?<=\Matched).*?(?=\[)'
MODSEC_V3_MESSAGE_MSG_PATTERN = r'(?<=\[msg\s\").*?(?=\"\])'

# parse the command line arguments
argParser = argparse.ArgumentParser()
argParser.add_argument('-f', type=str, help='input file with the ModSecurity audit log', required=False)
argParser.add_argument('-j', type=str, help='output file name for JSON format', required=False)
argParser.add_argument('-x', type=str, help='output file name for Excel format', required=False)
argParser.add_argument('-g', type=str, help='output file name for Graphs - PNG format', required=False)
argParser.add_argument(
    '-e',
    '--exclude',
    type=str,
    nargs='+',
    help='source IP addresses to exclude from the results as a list (e.g. -exclude 127.0.0.1 192.168.0.1)',
    required=False)
argParser.add_argument(
    '-i',
    '--include',
    type=str,
    nargs='+',
    help='source IP addresses to include only into the results as a list (e.g. -include 1.2.3.4 5.5.5.5)',
    required=False)
argParser.add_argument('-l', type=str, help='output file name for logging purposes', required=False)
argParser.add_argument(
    '--jsononeperline',
    action="store_true",
    help='events in output JSON will be enlisted one per line, otherwise by default JSON is humanreadable',
    default="False")
argParser.add_argument(
    '--version3',
    action="store_true",
    help='required if modsec_audit.log is produced by ModSecurity3',
    default="False")
argParser.add_argument('--jsonaudit', action='store_true', help='required if modsec_audit.log is JSON')
passedArgs = vars(argParser.parse_args())


input_filename = passedArgs['f']
JSON_OUTPUT_FILENAME = passedArgs['j']
JSON_ONE_PER_LINE = True if passedArgs['jsononeperline'] is True else False
VERSION3 = True if passedArgs['version3'] is True else False
# VERSION3 = passedArgs['version3']
# print(f'passedArgs["version3"]: {passedArgs["version3"]}')
# print(f'VERSION3: {VERSION3}, type(VERSION3): {type(VERSION3)}')
JSONAUDIT = True if passedArgs['jsonaudit'] is True else False

# Modsecurity JSON output for message doesn't comprise 'Message:' at the beggining of the string.
if JSONAUDIT:
    MODSEC_MESSAGE_MESSAGE_PATTERN = r'(?<=^).*(?=\.\s\[)'

# Modsecurity3 message information (if exists) starts with 'ModSecurity' string.
if VERSION3:
    a_pattern = re.compile(r'^---\w{8,10}---A--$')
    z_pattern = re.compile(r'^---\w{8,10}---Z--$')
    MODSEC_MESSAGE_MESSAGE_PATTERN = r'(?<=\ModSecurity:).*?(?=\[)'

XLSX_OUTPUT_FILENAME = passedArgs['x']
LOG_OUTPUT_FILENAME = passedArgs['l']
GRAPH_OUTPUT_FILENAME = passedArgs['g']
if passedArgs['include'] is not None:
    filter_include_table = passedArgs['include']
    FILTER_INCLUDE = True
    FILTER_EXCLUDE = False
elif passedArgs['exclude'] is not None:
    filter_exclude_table = passedArgs['exclude']
    FILTER_INCLUDE = False
    FILTER_EXCLUDE = True
else:
    FILTER_INCLUDE = False
    FILTER_EXCLUDE = False

datetimenow = strftime('%Y-%m-%d_%H-%M-%S', localtime())

RECORDS_TOTAL = 0
RECORDS_SKIPPED_CNT = 0
RECORDS_PROCESSED_CNT = 0


if input_filename is None:
    print('No parameter input_filename, looking for modsec_audit.log in current directory ...')
    input_filename = os.path.join(os.getcwd(), 'modsec_audit.log')
else:
    print(f'input_filename: {input_filename}')

FILE_BASENAME = str(os.path.splitext(os.path.split(input_filename)[-1])[0]) + '_' + str(datetimenow)
fileBaseOutputDir = os.path.join(os.path.dirname(input_filename), 'modsec_output')
if JSON_OUTPUT_FILENAME is None:
    JSON_OUTPUT_FILENAME = FILE_BASENAME + '.json'
if XLSX_OUTPUT_FILENAME is None:
    XLSX_OUTPUT_FILENAME = FILE_BASENAME + '.xlsx'
if LOG_OUTPUT_FILENAME is None:
    LOG_OUTPUT_FILENAME = FILE_BASENAME + '.log'
if GRAPH_OUTPUT_FILENAME is None:
    GRAPH_OUTPUT_FILENAME = FILE_BASENAME + '.png'


def safedictkey(dictname, keyname, default='None'):
    """Return value of nested keynames from dict.

        Return value of nested keynames from dict.
        If no such key (or nested keys) exist then returns default value.

    Args:
        dictname(dict): _description_. No default.
        keyname(string): _description_. No default.
        default(string): _description_. Default value to return if nothing found.

    Raises:
        Exception: _description_
    """
    # print(f'dictname: {dictname}')
    # print(f'keyname: {keyname}')
    # print(f'default : {default}')
    try:
        dictname_temp = dictname
        for value in keyname:
            dictname_temp = dict_return = dictname_temp[value]
        # print(f'dict_return: {dict_return}')
        return dict_return
    except Exception:
        return default


def get_params(string_in, separator=' ', defaultmissing='-', params_to_get=3):
    """Split string into requred number of parameters.

        Use defined separator and fulfill missing elements.

    Args:
        string_in(string): input string.
        separator(char): separator used to split input string. Default value ' ' (space).
        defaultmissing(string): value to replace missing list elements. Default '-'.
        params_to_get(varchar): how many parameters to take from string to list. Enforced to 3.

    Returns:
        var1: _description_
        var2: _description_
        var3: _description_
    """
    # print(f'string_in: {string_in}')
    # print(f'separator: {separator}')
    # print(f'defaultmissing: {defaultmissing}')
    rtr = str(string_in).split(separator)
    # print(f'rtr: {rtr}')
    if len(rtr) > params_to_get:
        rtr = []
        rtr.append(str(string_in))
    # for x in range(0, (params_to_get - len(rtr))):
    for _ in range(0, (params_to_get - len(rtr))):
        rtr.append(defaultmissing)
    # print('rtr one by one: ', rtr[0], rtr[1], rtr[2])
    return rtr[0], rtr[1], rtr[2]


def regular_expression_evaluate(
        string_in, regular_expression,
        group=True, to_split=False, to_split_value='/', to_split_column=-1):
    """_summary_

    Args:
        string_in (_type_): _description_
        regular_expression (_type_): _description_
        group (bool, optional): _description_. Defaults to True.
        to_split (bool, optional): _description_. Defaults to False.
        to_split_value (str, optional): _description_. Defaults to '/'.
        to_split_column (int, optional): _description_. Defaults to -1.

    Returns:
        _type_: _description_
    """
    try:
        if group and not to_split:
            re_value = re.search(regular_expression, string_in).group()
        elif group and to_split:
            re_value = re.search(regular_expression, string_in).group().split(to_split_value)[to_split_column]
        else:
            re_value = re.search(regular_expression, string_in)
    # except Exception as exception5:
    except Exception:
        re_value = '?'
    return re_value


def modsec_save_json(dict_to_save, file_to_save, one_per_line):
    """_summary_

    Exports modsec_audit events to *.json file.
    one_per_line True -> file formatted likewise when logging set to JSON in modsecurity.conf,
    one_per_line False -> human readable JSON output

    Args:
        dict_to_save (_type_): _description_
        file_to_save (_type_): _description_
        one_per_line (_type_): _description_
    """
    try:
        if not os.path.isdir(fileBaseOutputDir):
            os.mkdir(fileBaseOutputDir)
        file_out = open(os.path.join(fileBaseOutputDir, file_to_save), 'w')
        if one_per_line:
            for line in dict_to_save:
                file_out.write(json.dumps(line))
                file_out.write('\n')
            file_out.close()
        else:
            for line in dict_to_save:
                file_out.write(json.dumps(line, indent=4, sort_keys=False))
                file_out.write('\n')
            file_out.close()
    except Exception as exception:
        print(f'modsec_save_json() thrown exception: {exception}')


def modsec_save_xlsx(modsec_dict, output_xlsx_filename, output_with_graphs):
    """_summary_

    Exports processed modsec_audit events into XLSX formatted file.

    Args:
        modsec_dict (_type_): List of audit events as JSON
        output_xlsx_filename (_type_): file to save the report
        output_with_graphs (_type_): _description_

    Returns:
        _type_: _description_
    """
    modsec_header_xlsx = ['transaction_id', 'event_time', 'remote_address', 'request_host',
                          'request_useragent', 'request_line', 'request_line_method', 'request_line_url',
                          'request_line_protocol', 'response_protocol', 'response_status',
                          'action', 'action_phase', 'action_message',
                          'message_type', 'message_description', 'message_rule_id', 'message_rule_file',
                          'message_msg', 'message_severity', 'message_accuracy', 'message_maturity', 'full_message_line'
                          ]
    workbook = openpyxl.Workbook()
    ws1 = workbook.active
    ws1.title = 'Modsec_entries'
    ws1.append(modsec_header_xlsx)

    for entry_mod in modsec_dict:
        try:
            transaction_id = entry_mod['transaction']['transaction_id']
            event_time = entry_mod['transaction']['time']
            remote_address = entry_mod['transaction']['remote_address']
            request_line = entry_mod['request']['request_line']
            request_line_method, request_line_url, request_line_protocol = get_params(
                string_in=request_line, defaultmissing='-', params_to_get=3)
            request_headers_useragent = safedictkey(entry_mod, ['request', 'headers', 'User-Agent'], '-')
            request_headers_host = safedictkey(entry_mod, ['request', 'headers', 'Host'], '-')
            response_protocol = safedictkey(entry_mod, ['response', 'protocol'], '-')
            response_status = safedictkey(entry_mod, ['response', 'status'], '-')
            audit_data_producer = safedictkey(entry_mod, ['audit_data', 'producer'], '-')  # noqa: F841
            audit_data_server = safedictkey(entry_mod, ['audit_data', 'server'], '-')  # noqa: F841
            audit_data_enginemode = safedictkey(entry_mod, ['audit_data', 'Engine-Mode'], '-')  # noqa: F841
            audit_data_action_intercepted = 'intercepted' if (
                safedictkey(entry_mod, ['audit_data', 'action', 'intercepted'], '-') is True) else '-'
            audit_data_action_message = safedictkey(entry_mod, ['audit_data', 'action', 'message'], '-')
            audit_data_action_phase = safedictkey(entry_mod, ['audit_data', 'action', 'phase'], '-')

            if ('messages' in entry_mod['audit_data']) and (len(entry_mod['audit_data']) > 0):
                if len(entry_mod['audit_data']['messages']) > 1:
                    audit_data_message_type = 'multiple'
                else:
                    audit_data_message_type = 'single'
                for each in entry_mod['audit_data']['messages']:
                    audit_data_message_message = regular_expression_evaluate(each, MODSEC_MESSAGE_MESSAGE_PATTERN)
                    audit_data_message_file = regular_expression_evaluate(
                        each, MODSEC_MESSAGE_FILE_PATTERN, to_split=True, to_split_value='/', to_split_column=-1)
                    audit_data_message_id = regular_expression_evaluate(each, MODSEC_MESSAGE_ID_PATTERN)
                    audit_data_message_msg = regular_expression_evaluate(each, MODSEC_MESSAGE_MSG_PATTERN)
                    audit_data_message_severity = regular_expression_evaluate(each, MODSEC_MESSAGE_SEVERITY_PATTERN)
                    audit_data_message_maturity = regular_expression_evaluate(each, MODSEC_MESSAGE_MATURITY_PATTERN)
                    audit_data_message_accuracy = regular_expression_evaluate(each, MODSEC_MESSAGE_ACCURACY_PATTERN)
                    # audit_data_message_tags = [] # TAGS not in use currently
                    ws1.append([transaction_id, event_time, remote_address, request_headers_host,
                                request_headers_useragent, request_line, request_line_method,
                                request_line_url, request_line_protocol, response_protocol, response_status,
                                audit_data_action_intercepted, audit_data_action_phase, audit_data_action_message,
                                audit_data_message_type, audit_data_message_message, audit_data_message_id,
                                audit_data_message_file, audit_data_message_msg, audit_data_message_severity,
                                audit_data_message_accuracy, audit_data_message_maturity, each
                                ])
            else:
                audit_data_message_type = 'None'
                each = 'None'
                # print('M error - message not found for transaction_id :', transaction_id)
                audit_data_message_message = audit_data_message_file = audit_data_message_id = \
                    audit_data_message_msg = audit_data_message_severity = audit_data_message_maturity = \
                    audit_data_message_accuracy = '-'
                ws1.append([transaction_id, event_time, remote_address, request_headers_host, request_headers_useragent,
                            request_line, request_line_method, request_line_url, request_line_protocol,
                            response_protocol, response_status, audit_data_action_intercepted,
                            audit_data_action_phase, audit_data_action_message, audit_data_message_type,
                            audit_data_message_message, audit_data_message_id, audit_data_message_file,
                            audit_data_message_msg, audit_data_message_severity, audit_data_message_accuracy,
                            audit_data_message_maturity, each
                            ])
        except Exception as exception:
            print(f'Exception at modsec_save_xlsx() :{exception}, transaction_id :{transaction_id}')

    if 'error' not in output_with_graphs:
        img = openpyxl.drawing.image.Image(output_with_graphs)
        ws2 = workbook.create_sheet('Graphs')
        ws2.add_image(img)

    try:
        if not os.path.isdir(fileBaseOutputDir):
            os.mkdir(fileBaseOutputDir)
        file_out = os.path.join(fileBaseOutputDir, output_xlsx_filename)
        workbook.save(filename=file_out)
    except Exception as exception:
        print(f'modsec_save_xlsx() has thrown exception: {exception}')

    return True


def modsec_view_graphs(modsec_dict):  # noqa: C901
    """_summary_

    Module to visualize audit log as graphs

    Args:
        modsec_dict (_type_): list of modsec_audit events given as a dictionary

    Returns:
        _type_: png file output or string 'error' in case no valid image created
    """
    if len(modsec_dict) < 1:
        sys.exit('Error: No logs to visualize. Check log and Include/Exclude filters')

    # GRAPHS PART I
    # Collect information into lists/dicts to make particular graphs

    src_ip_tab = []
    event_time_action = []
    event_messages = []
    intercepted_reason = []
    event_rules = []
    for entry_mod in modsec_dict:
        try:
            # Graph data for "TOP 10 IP source addresses"
            src_ip_tab.append(entry_mod['transaction']['remote_address'])

            # Graph data for "Modsecurity Events reported vs intercepted"
            if (VERSION3 is False) and \
                ('action' in entry_mod['audit_data'].keys() and
                    'intercepted' in entry_mod['audit_data']['action'].keys()):
                event_time_action.append([entry_mod['transaction']['time'], True])

            elif (VERSION3 is True) and len(entry_mod['audit_data']) > 0:
                for each_msg in entry_mod['audit_data']['messages']:
                    if each_msg.startswith("ModSecurity: Access denied"):
                        event_time_action.append([entry_mod['transaction']['time'], True])
                    else:
                        event_time_action.append([entry_mod['transaction']['time'], False])
            else:
                # No 'intercepted'
                event_time_action.append([entry_mod['transaction']['time'], False])
        except Exception as exception2:
            print(f'Exception in Graph TOP 10 IP source addresses: {exception2}')

        # Graph data for "TOP 20 rule hits"
        try:
            if 'messages' in entry_mod['audit_data'].keys():
                messages = safedictkey(entry_mod, ['audit_data', 'messages'], '-')
                for each in messages:
                    event_messages.append(each)
                    rule_id = regular_expression_evaluate(each, MODSEC_MESSAGE_ID_PATTERN)
                    rule_msg = regular_expression_evaluate(each, MODSEC_MESSAGE_MSG_PATTERN)
                    rule_severity = regular_expression_evaluate(each, MODSEC_MESSAGE_SEVERITY_PATTERN)
                    rule_file = regular_expression_evaluate(each, MODSEC_MESSAGE_FILE_PATTERN)

                    # Cut the [msg] to 27 chars if it is longer than 30 chars.
                    # If [msg] and [id] not found then treat message description as the [msg]
                    if len(rule_msg) > 30:
                        rule_msg = rule_msg[:27] + '...'
                    if rule_msg == '?' and rule_id == '-':
                        rule_msg = str(each)[:30]
                    rule_descr = 'id: ' + str(rule_id) + ', sev: ' + str(rule_severity) + ', msg: ' + str(rule_msg)
                    event_rules.append([rule_id, rule_msg, rule_severity, rule_file, rule_descr])
            else:
                # Skip modsec_audit entries without [message] part
                pass
        except Exception as exception3:
            print(f'Exception in TOP 20 rule hits: {exception3}')
            print('for transaction_id :', safedictkey(entry_mod, ['transaction', 'transaction_id'], '-'))

        # Graph data for "TOP 10 Attacks intercepted"
        try:
            if (VERSION3 is False) and ('action' in entry_mod['audit_data']):
                msg = entry_mod['audit_data']['action']['message']
                if len(msg) > 60:
                    msg = msg[:50] + '...'
                intercepted_reason.append(
                    [entry_mod['audit_data']['action']['phase'], msg,
                        'phase ' + str(entry_mod['audit_data']['action']['phase']) + ': ' + msg])
            elif (VERSION3 is True) and len(entry_mod['audit_data']) > 0:
                for each_msg in entry_mod['audit_data']['messages']:
                    if each_msg.startswith("ModSecurity: Access denied"):
                        msg = regular_expression_evaluate(each_msg, MODSEC_V3_MESSAGE_MSG_PATTERN)
                        if len(msg) > 60:
                            msg = msg[:50] + '...'
                        phase = regular_expression_evaluate(each_msg, MODSEC_V3_MESSAGE_PHASE_PATTERN)
                        intercepted_reason.append([phase, msg, 'phase ' + phase + ': ' + msg])

        except Exception as exception:
            print(f'Exception in Graph TOP 10 Attacks intercepted {exception}')

    # Modsecurity events Passed vs Intercepted
    np_event_time_action = np.array(event_time_action)
    event_times1 = np_event_time_action[:, 0]
    try:
        event_times = list(map(lambda x: datetime.strptime(x.replace('--', '-'),
                           LOG_TIMESTAMP_FORMAT).replace(tzinfo=None), event_times1))
    except ValueError:
        event_times = list(map(lambda x: datetime.strptime(x.replace('--', '-'),
                           LOG_TIMESTAMP_FORMAT_TIMEMS).replace(tzinfo=None), event_times1))
    except Exception as exception:
        print(f'Exception timestamp extraction in Passed vs Intercepted {exception}')
    event_action = np_event_time_action[:, 1]
    event_times_min = min(event_times)
    event_times_max = max(event_times)
    event_times_range = event_times_max - event_times_min
    event_times_range_seconds = int(event_times_range.total_seconds())
    event_times_range_minutes = int(event_times_range.total_seconds() / 60)
    if event_times_range_minutes < 60:
        periods = str(int(event_times_range_seconds / 1)) + 's'
    else:
        periods = str(int(event_times_range_minutes / 30)) + 'min'
    events_df = pd.DataFrame({
        'date': pd.to_datetime(event_times),
        'action': event_action
    })
    intercepted = []
    passed = []
    passed_cnt2 = 0
    intercepted_cnt2 = 0
    for row in events_df['action']:
        if row == 'True':
            intercepted.append(1)
            passed.append(0)
            intercepted_cnt2 += 1
        else:
            intercepted.append(0)
            passed.append(1)
            passed_cnt2 += 1
    events_df['intercepted'] = intercepted
    events_df['passed'] = passed

    # GRAPHS PART II

    # TOP 10 IP addresses Graph - data preparation
    ipaddr_cnt = Counter()
    for word in src_ip_tab:
        ipaddr_cnt[word] += 1
    ipaddr_cnt_top10 = dict(ipaddr_cnt.most_common(10))

    # TOP 10 Interception Reason - data preparation
    intercepted_cnt = Counter()
    for word in intercepted_reason:
        intercepted_cnt[word[2]] += 1
    intercepted_cnt_top10 = dict(intercepted_cnt.most_common(10))
    # TOP 20 Rule IDs hit - data preparation
    event_messages_ids = Counter()
    for word in event_rules:
        event_messages_ids[word[4]] += 1
    event_messages_ids_top20 = dict(event_messages_ids.most_common(20))

    # GRIDS VERSION BEGIN
    fig = plt.figure(0)
    grid = plt.GridSpec(3, 3, wspace=1.1, hspace=1.1)
    ax1 = plt.subplot(grid[0, 0:3])
    ax21 = plt.subplot(grid[1, 0])
    ax22 = plt.subplot(grid[2, 0])
    ax31 = plt.subplot(grid[1, 1])
    ax32 = plt.subplot(grid[2, 1])
    ax41 = plt.subplot(grid[1, 2])
    ax42 = plt.subplot(grid[2, 2])

    # Graph Included or Excluded
    modsec_inc_exc_str = ''
    if FILTER_INCLUDE:
        modsec_inc_exc_str = 'Filter INCLUDE active. Skipped the rest of ' + str(RECORDS_SKIPPED_CNT) + \
                             ' events where source IP address NOT in: ' + str(filter_include_table)
    elif FILTER_EXCLUDE:
        modsec_inc_exc_str = 'Filter EXCLUDE active. Skipped the rest of ' + str(RECORDS_SKIPPED_CNT) + \
            ' events where source IP address in: ' + str(filter_exclude_table)
    else:
        modsec_inc_exc_str = 'Filter INCLUDE/EXCLUDE non-active.'

    title_timespan = 'Analysis of ' + str(RECORDS_PROCESSED_CNT) + ' modsecurity events in timespan: ' + \
                     str(event_times_min.strftime("%Y-%m-%d_%H:%M")) + ' - ' + \
                     str(event_times_max.strftime("%Y-%m-%d_%H:%M")) + '\n'
    title_total = 'Total number of events found in logfile ' + str(RECORDS_TOTAL) + \
                  ' (output always trimmed to variable MAXEVENTS = ' + str(MAXEVENTS) + ' )\n'
    title_reported_intercepted = 'events passed: ' + str(passed_cnt2) + \
                                 ' , events intercepted: ' + str(intercepted_cnt2)
    plot_title = title_timespan + title_total + modsec_inc_exc_str + '\n\n' + title_reported_intercepted
    if event_times_range_seconds < 1800:
        short_time_range_message = 'Creating timeline graph is not available for timespan ' + \
                                   str(event_times_range_seconds) + ' seconds, skipping ...'
        plt.subplot(ax1)
        plt.text(0.5, 0.5, short_time_range_message, horizontalalignment='center', verticalalignment='center')
        plt.title(plot_title)
    else:
        ex = events_df.groupby(pd.Grouper(key='date', freq=periods)).sum(numeric_only=True)
        ex.plot(ax=ax1, kind='bar', title=plot_title, stacked=True, color={'purple', 'red'}, fontsize=7, rot=45)

    # Bar chart "TOP 10 IP addresses"
    plt.subplot(ax21)
    patches, texts, autotexts = plt.pie(ipaddr_cnt_top10.values(), autopct='%1.1f%%',
                                        shadow=True, startangle=90, radius=1.0)
    plt.title(f'TOP {len(ipaddr_cnt_top10)} IP addresses (out of total {len(ipaddr_cnt)}) ',
              bbox={'facecolor': '0.8', 'pad': 5})

    # Legend for chart "TOP 10 IP addresses"
    # x_value = np.char.array(list(ipaddr_cnt_top10.keys()))
    y_value = np.array(list(ipaddr_cnt_top10.values()))
    labels = [f'{i} --> {j} hits' for i, j in
              zip(ipaddr_cnt_top10.keys(), ipaddr_cnt_top10.values())]
    if len(ipaddr_cnt_top10.keys()) >= 1:
        patches, labels, dummy = zip(*sorted(zip(patches, labels, y_value), key=lambda x: x[2], reverse=True))
        plt.subplot(ax22)
        plt.axis('off')
        plt.legend(patches, labels, loc='center left', bbox_to_anchor=(-0.1, 1.), fontsize=7)

    # Bar chart "TOP 10 Attacks intercepted"
    plt.subplot(ax31)
    patches, texts, autotexts = plt.pie(intercepted_cnt_top10.values(),
                                        autopct='%1.1f%%', shadow=True, startangle=90, radius=1.0, normalize=True)
    [_.set_fontsize(7) for _ in texts]
    plt.title('TOP 10 Attacks intercepted', bbox={'facecolor': '0.8', 'pad': 5})

    # Legend for chart "TOP 10 Attacks intercepted"
    # x_value = np.char.array(list(intercepted_cnt_top10.keys()))
    y_value = np.array(list(intercepted_cnt_top10.values()))
    labels = [f'{i} --> {j} hits'
              for i, j in zip(intercepted_cnt_top10.keys(), intercepted_cnt_top10.values())]
    if len(intercepted_cnt_top10.values()) >= 1:
        patches, labels, dummy = zip(*sorted(zip(patches, labels, y_value), key=lambda x: x[2], reverse=True))
        plt.subplot(ax32)
        plt.axis('off')
        plt.legend(patches, labels, loc='center left', bbox_to_anchor=(-0.1, 1.), fontsize=7)
    else:
        plt.subplot(ax32)
        plt.axis('off')
        plt.text(
            0.5, 0.5, 'No intercepted events found for given data set',
            horizontalalignment='center', verticalalignment='center')

    # Bar chart "TOP 20 Rule IDs hit"
    plt.subplot(ax41)
    patches, texts, autotexts = plt.pie(
        event_messages_ids_top20.values(),
        autopct='%1.1f%%', shadow=True, startangle=90, radius=1.0, normalize=True)
    _ = autotexts
    plt.title('TOP 20 Rule IDs hit', bbox={'facecolor': '0.8', 'pad': 5})

    # Legend for chart "TOP 20 Rule IDs hit"
    # x_value = np.char.array(list(event_messages_ids_top20.keys()))
    y_value = np.array(list(event_messages_ids_top20.values()))
    labels = [
        f'{i} --> {j} hits' for i, j in zip(event_messages_ids_top20.keys(),
                                            event_messages_ids_top20.values())]
    if len(event_messages_ids_top20.keys()) >= 1:
        patches, labels, dummy = zip(*sorted(zip(patches, labels, y_value),
                                     key=lambda x_value: x_value[2], reverse=True))
        plt.subplot(ax42, axis='off')
        plt.axis('off')
        plt.legend(patches, labels, loc='center left', bbox_to_anchor=(-0.1, 1.), fontsize=7)

    # GRID VERSION END

    graph_title = 'Modsecurity events ' + str(datetimenow) + \
        ' from file: ' + input_filename + ' first ' + str(MAXEVENTS) + ' analyzed'
    fig.canvas.set_window_title(graph_title)
    fig.set_size_inches(18, 11)
    # plt.get_current_fig_manager().window.wm_geometry("+10+10")
    try:
        if not os.path.isdir(fileBaseOutputDir):
            os.mkdir(fileBaseOutputDir)
        file_out = os.path.join(fileBaseOutputDir, GRAPH_OUTPUT_FILENAME)
        plt.savefig(file_out)
        return file_out
    except Exception as exception:
        print(f'modsec_view_graphs.savefig() thrown exception: {exception}')
        return 'error'


def modsec_log_to_info(single_entry):
    """_summary_

    Module gets piece of log for single modsecurity event and transform into dict (JSON)
    according to standard JSON logging

    Args:
        single_entry (_type_): text consisted of many lines for single modsecurity event.
                               Expected it starting with section 'A' and ending with section 'Z'
    Returns:
        dict: modsec_audit entry converted into JSON
    """
    modsec_dict = OrderedDict()
    a_header = single_entry[0]
    if VERSION3:
        e_separator = a_header[a_header.find('^---') + 4:a_header.find('---A--')]
    else:
        e_separator = a_header[a_header.find('^--') + 3:a_header.find('-A-')]
    item_number = 0
    item_kv = OrderedDict()
    try:
        for item in single_entry:
            if item.__contains__(e_separator):
                item_kv[item.rstrip()[-3:-2:]] = item_number
            item_number += 1
        item_keys = list(item_kv.keys())
        item_kv_full = OrderedDict()
        for item_letter in item_keys:
            if item_letter in modsec_event_types:
                i = int(item_kv[item_letter]) + 1
                j = item_kv[item_keys[item_keys.index(item_letter) + 1]]
                item_kv_full[item_letter] = single_entry[i:j]

        modsec_a = item_kv_full['A'][0]
        modsec_b = item_kv_full['B']
        modsec_f = item_kv_full['F']
        modsec_h = item_kv_full['H']

        modsec_b_headers = dict(map(lambda s: [s[0:s.find(': ')], s[s.find(': ') + 2:]], modsec_b[1:-1]))
        modsec_f_headers = dict(map(lambda s: [s, '-']
                                if len(s.split(': ')) == 1
                                else [s[0:s.find(': ')], s[s.find(': ') + 2:]], modsec_f[1:-1]))
        modsec_h_dict = OrderedDict()
        for elem in modsec_h:
            if elem.startswith('Message:') or elem.startswith('ModSecurity:'):
                if 'messages' not in modsec_h_dict:
                    modsec_h_dict['messages'] = [elem]
                else:
                    modsec_h_dict['messages'].append(elem)
            elif elem.startswith('Apache-Handler:'):
                if 'handlers_messages' not in modsec_h_dict:
                    modsec_h_dict['handlers_messages'] = [elem]
                else:
                    modsec_h_dict['handlers_messages'].append(elem)
            elif elem.startswith('Apache-Error:'):
                if 'error_messages' not in modsec_h_dict:
                    modsec_h_dict['error_messages'] = [elem]
                else:
                    modsec_h_dict['error_messages'].append(elem)
            elif elem.startswith('Producer:'):
                modsec_h_dict['producer'] = elem.split(': ')[1].strip(' .').split('; ')
            elif elem.startswith('Engine-Mode:'):
                modsec_h_dict['Engine-Mode'] = elem.split(': ')[1].strip('"')
            elif elem.startswith('Server:'):
                modsec_h_dict['server'] = elem.split(': ')[1]
            elif elem.startswith('Action: '):
                modsec_h_dict['action'] = {}
                if 'ntercepted' in elem:
                    modsec_h_dict['action']['intercepted'] = True
                    modsec_h_dict['action']['phase'] = int(elem[elem.find('phase') + 6])
                    modsec_h_dict['action']['message'] = modsec_h_dict['messages'][-1].split('.')[1].strip()
            elif elem.startswith('Stopwatch2'):
                modsec_h_dict['stopwatch'] = {}
                for stopw in elem.split(' '):
                    if '=' in stopw:
                        modsec_h_dict['stopwatch'][stopw.split('=')[0]] = int(stopw.split('=')[1].strip(','))

            else:
                pass
        modsec_a_split = modsec_a.split()
        modsec_dict['transaction'] = {
            'time': modsec_a_split[0].replace('[', '') + ' ' + modsec_a_split[1].replace(']', ''),
            'transaction_id': modsec_a_split[2],
            'remote_address': modsec_a_split[3],
            'remote_port': modsec_a_split[4],
            'local_address': modsec_a_split[5],
            'local_port': modsec_a_split[6]}
        if len(modsec_b) > 0:
            modsec_dict['request'] = {'request_line': modsec_b[0], 'headers': modsec_b_headers}
        else:
            modsec_dict['request'] = 'None'

        if len(modsec_f_headers) > 3:
            modsec_dict['response'] = OrderedDict()
            try:
                modsec_dict['response'] = {
                    'protocol': modsec_f[0].split(' ')[0],
                    'status': modsec_f[0].split(' ')[1],
                    'status_text': ' '.join(modsec_f[0].split(' ')[2:]),
                    'headers': modsec_f_headers}
            except Exception as exception:
                print(f'Exception at modsec_dict["response"]: {exception}')
                modsec_dict['response'] = 'None'
        else:
            modsec_dict['response'] = 'None'
        modsec_dict['audit_data'] = OrderedDict()
        modsec_dict['audit_data'] = modsec_h_dict
    except Exception as exception:
        print(f'modsec_log_to_info() error found: {exception} when processing: {single_entry}')
        modsec_dict = 'ERROR'

    return modsec_dict


def process_modsec_audit_std(audit_input_file):
    """_summary_

    Args:
        audit_input_file (_type_): _description_

    Returns:
        _type_: _description_
    """
    try:
        with open(audit_input_file, 'r', encoding='cp437') as modsec_f_handler:
            pmas_modsec_table = []
            for log_line in modsec_f_handler:
                if a_pattern.search(log_line):
                    modsec_entry = [log_line]
                    for entry_log in modsec_f_handler:
                        if z_pattern.search(entry_log):
                            modsec_entry.append(entry_log.rstrip())
                            pmas_modsec_table.append(modsec_entry)
                            break
                        else:
                            modsec_entry.append(entry_log.rstrip())
        return pmas_modsec_table
    except FileNotFoundError:
        print(f'File "{audit_input_file}" not found')
        return 'error'
    except Exception as exception:
        print(f'Error found {exception} during read file {audit_input_file}')
        return 'error'


def process_modsec_audit_json(audit_input_file):
    """_summary_

    Args:
        audit_input_file (_type_): _description_

    Returns:
        _type_: _description_
    """
    line_number = 0
    pmaj_modsec_table = []
    try:
        with open(audit_input_file, 'r', encoding='utf-8', errors='ignore') as modsec_f_handler:
            for log_line in modsec_f_handler:
                line_number += 1
                try:
                    jline = json.loads(log_line)
                    pmaj_modsec_table.append(jline)
                except Exception as e_logline:
                    print(f'Error {e_logline} found during reading file {audit_input_file} at line {line_number}')
        return pmaj_modsec_table
    except FileNotFoundError:
        print(f'File "{audit_input_file}" not found')
        return 'error'
    except Exception as exception:
        print(f'Error {exception} found during read file {audit_input_file} at line {line_number}')
        return 'error'


if __name__ == "__main__":
    if JSONAUDIT is True:
        main_modsec_table = process_modsec_audit_json(input_filename)
    else:
        main_modsec_table = process_modsec_audit_std(input_filename)
    if isinstance(main_modsec_table, str) and main_modsec_table in 'error':
        print('No modsecurity audit log found')
    elif isinstance(main_modsec_table, list) and len(main_modsec_table) == 0:
        print('No modsecurity events found in the specified file')
    else:
        RECORDS_TOTAL = len(main_modsec_table)
        modsec_entries = []
        for modsec_entry in main_modsec_table:
            if JSONAUDIT is False:
                json_modsec_entry = modsec_log_to_info(modsec_entry)
            else:
                json_modsec_entry = modsec_entry
            if FILTER_INCLUDE:
                if dict(json_modsec_entry)['transaction']['remote_address'] in filter_include_table:
                    modsec_entries.append(json_modsec_entry)
                    RECORDS_PROCESSED_CNT += 1
                else:
                    RECORDS_SKIPPED_CNT += 1
            elif FILTER_EXCLUDE:
                if dict(json_modsec_entry)['transaction']['remote_address'] not in filter_exclude_table:
                    modsec_entries.append(json_modsec_entry)
                    RECORDS_PROCESSED_CNT += 1
                else:
                    RECORDS_SKIPPED_CNT += 1
            elif (isinstance(json_modsec_entry, str)) and ('ERROR' in json_modsec_entry):
                RECORDS_SKIPPED_CNT += 1
            else:
                modsec_entries.append(json_modsec_entry)
                RECORDS_PROCESSED_CNT += 1
            if RECORDS_PROCESSED_CNT >= MAXEVENTS:
                print(f'----- Limit {MAXEVENTS} of events has been reached. -----')
                print(f'----- The rest of {str(RECORDS_TOTAL - MAXEVENTS - RECORDS_SKIPPED_CNT)}'
                      ' events will be skipped ... -----')
                break
        print(f'----- modsec_audit events processed: {RECORDS_PROCESSED_CNT} -----')
        print(f'----- modsec_audit events skipped by INCLUDED/EXCLUDED options or INVALID: {RECORDS_SKIPPED_CNT} -----')
        if len(modsec_entries) < 1:
            print('ERROR : modsec_audit entries to analyze not found with used filters')
        else:
            modsec_save_json(modsec_entries, JSON_OUTPUT_FILENAME, JSON_ONE_PER_LINE)
            output_with_graphs = modsec_view_graphs(modsec_entries)
            modsec_save_xlsx(modsec_entries, XLSX_OUTPUT_FILENAME, output_with_graphs)
