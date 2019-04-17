# 2019.01 - molu8bits (at) gmail (dot) com
# modsecurity-parser.py
# Script to analyze modsecurity audit log and present outputs as:
# - json file (compatible with default JSON logging)
# - xlsx report
# - png with graphs
import matplotlib
matplotlib.use('Agg')
import os, argparse, re, json
from collections import OrderedDict, Counter
from time import localtime,strftime,strptime
from datetime import datetime
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import openpyxl


DEBUG = False
MAXEVENTS = 90000
SAVEOUTPUTJSON = True
JSON_ONE_PER_LINE = False
FILTER_INCLUDE = True
FILTER_EXCLUDE = True
LOG_TIMESTAMP_FORMAT = '%d/%b/%Y:%H:%M:%S %z'       # e.g. "01/Mar/2018:05:26:41 +0100"
LOG_TIMESTAMP_FORMAT_SHORT = '%Y-%m-%d_%H:%M'


# modsec_patterns
a_pattern = re.compile('^--\w{6,10}-A--$')
z_pattern = re.compile('^--\w{6,10}-Z--$')
modsec_event_types = ['A','B','C','E','F','H','I','J','K']
modsec_message_file_pattern = r'(?<=\[file\s\").*?(?="\])'
modsec_message_msg_pattern = r'(?<=\[msg\s\").*?(?=\"\])'
modsec_message_id_pattern = r'(?<=\[id\s\").*?(?=\"\])'
modsec_message_severity_pattern = r'(?<=\[severity\s\").*?(?=\"\])'
modsec_message_maturity_pattern = r'(?<=\[maturity\s\").*?(?=\"\])'
modsec_message_accuracy_pattern = r'(?<=\[accuracy\s\").*?(?=\"\])'
modsec_message_message_pattern = r'(?<=Message:).*?(?=\.\ \[)'
modsec_v3_message_phase_pattern = r'(?<=\(phase).*?(?=\))'
#modsec_v3_message_phase_pattern = r'(?:\(phase).*?(?:\))'           # (phase 2)
#modsec_v3_message_phase_pattern = r'(?:\(phase).*?(?=\))'
#modsec_v3_message_message_pattern = r'(?<=\Message:).*?(?=\[)'
modsec_v3_message_message_pattern = r'(?<=\Matched).*?(?=\[)'
modsec_v3_message_msg_pattern = r'(?<=\[msg\s\").*?(?=\"\])'

# parse the command line arguments
argParser = argparse.ArgumentParser()
argParser.add_argument('-f', type=str, help='input file with the ModSecurity audit log', required=False)
argParser.add_argument('-j', type=str, help='output file name for JSON format', required=False)
argParser.add_argument('-x', type=str, help='output file name for Excel format', required=False)
argParser.add_argument('-g', type=str, help='output file name for Graphs - PNG format', required=False)
argParser.add_argument('-e','--exclude', type=str, nargs='+', help='source IP addresses to exclude from the results as a list (e.g. -exclude 127.0.0.1 192.168.0.1)', required=False)
argParser.add_argument('-i','--include', type=str, nargs='+', help='source IP addresses to include only into the results as a list (e.g. -include 1.2.3.4 5.5.5.5)', required=False)
argParser.add_argument('-l', type=str, help='output file name for logging purposes', required=False)
argParser.add_argument('--jsononeperline', action="store_true", help='events in output JSON will be enlisted one per line, otherwise by default JSON is humanreadable', default="False")
argParser.add_argument('--version3', action="store_true", help='required if modsec_audit.log is produced by ModSecurity3', default="False")
argParser.add_argument('--jsonaudit', action='store_true', help='required if modsec_audit.log is JSON')
passedArgs = vars(argParser.parse_args())

inputFileName = passedArgs['f']
jsonOutputFilename = passedArgs['j']
JSON_ONE_PER_LINE = True if passedArgs['jsononeperline'] is True else False
version3 = True if passedArgs['version3'] is True else False
jsonaudit = True if passedArgs['jsonaudit'] is True else False

# Modsecurity JSON output for message doesn't comprise 'Message:' at the beggining of the string.
if jsonaudit:
    modsec_message_message_pattern = r'(?<=^).*(?=\.\s\[)'

# Modsecurity3 message information (if exists) starts with 'ModSecurity' string.
if version3:
    a_pattern = re.compile('^---\w{8,10}---A--$')
    z_pattern = re.compile('^---\w{8,10}---Z--$')
    modsec_message_message_pattern = r'(?<=\ModSecurity:).*?(?=\[)'

xlsxOutputFilename = passedArgs['x']
logOutputFilename = passedArgs['l']
graphOutputFilename = passedArgs['g']
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

records_total = 0
records_skipped_cnt = 0
records_processed_cnt = 0

def safedictkey(dictname, keyname, default='None'):
    """
        Returns value of nested keynames from dict. If no such key (or nested keys) exist then returns default value
    """
    try:
        dictname_temp = dictname
        for value in keyname:
            dictname_temp = d = dictname_temp[value]
        return d
    except Exception:
        return default

def get_params(string_in, separator=' ', defaultmissing='-', params_to_get=3):
    """
    Split string using 'separator' into required number of parameters. Fulfill missing parameters with 'defaultmissing'
    Current limitation: hardcoded return always 3 of them
    """
    rtr = str(string_in).split(separator)
    if len(rtr) > params_to_get:
        rtr = []
        rtr.append(str(string_in))
    for x in range(0, (params_to_get - len(rtr))):
        rtr.append(defaultmissing)
    return rtr[0],rtr[1],rtr[2]

def regular_expression_evaluate(string_in, regular_expression, group=True, to_split=False, to_split_value='/', to_split_column=-1):
    try:
        if group and not to_split:
            re_value = re.search(regular_expression, string_in).group()
        elif group and to_split:
            re_value = re.search(regular_expression, string_in).group().split(to_split_value)[to_split_column]
        else:
            re_value = re.search(regular_expression, string_in)
    except Exception as e5:
        re_value = '?'
    return re_value


if inputFileName == None:
    print('No parameter inputFileName, looking for modsec_audit.log in current directory ...')
    inputFileName = os.path.join(os.getcwd(), 'modsec_audit.log')
else:
    print('inputFileName :', inputFileName)

fileBaseName = str(os.path.splitext(os.path.split(inputFileName)[-1])[0]) + '_' + str(datetimenow)
fileBaseOutputDir = os.path.join(os.path.dirname(inputFileName), 'modsec_output')
if jsonOutputFilename == None:
    jsonOutputFilename = fileBaseName + '.json'
if xlsxOutputFilename == None:
    xlsxOutputFilename = fileBaseName + '.xlsx'
if logOutputFilename == None:
    logOutputFilename = fileBaseName + '.log'
if graphOutputFilename == None:
    graphOutputFilename = fileBaseName + '.png'


def modsecSaveJson(dictToSave, fileToSave, onePerLine):
    """
    Exports modsec_audit events to *.json file.
    onePerLine True -> file formatted likewise when logging set to JSON in modsecurity.conf,
    onePerLine False -> human readable JSON output
    """
    try:
        if not os.path.isdir(fileBaseOutputDir):
            os.mkdir(fileBaseOutputDir)
        fOut = open(os.path.join(fileBaseOutputDir, fileToSave), 'w')
        if onePerLine:
            for line in dictToSave:
                fOut.write(json.dumps(line))
                fOut.write('\n')
            fOut.close()
        else:
            for line in dictToSave:
                fOut.write(json.dumps(line, indent=4, sort_keys=False))
                fOut.write('\n')
            fOut.close()
    except Exception as e:
        print('modsecSaveJson() thrown exception: %s', e)
    pass

def modsecSaveXLSX(modsecDict, outputXLSXFileName, outputWithGraphs):
    """
    Exports processed modsec_audit events into XLSX formatted file.
    :param modsecDict: List of audit events as JSON
    :param outputXLSXFileName: file to save the report
    :return:
    """
    modsec_header_xlsx = ['transaction_id', 'event_time', 'remote_address', 'request_host',
                          'request_useragent','request_line', 'request_line_method', 'request_line_url', 'request_line_protocol',
                          'response_protocol', 'response_status',
                          'action','action_phase', 'action_message',
                          'message_type', 'message_description', 'message_rule_id', 'message_rule_file',
                          'message_msg', 'message_severity', 'message_accuracy', 'message_maturity', 'full_message_line'
                          ]
    wb = openpyxl.Workbook()
    ws1 = wb.active
    ws1.title = 'Modsec_entries'
    ws1.append(modsec_header_xlsx)

    for entry_mod in modsecDict:
        try:
            transaction_id = entry_mod['transaction']['transaction_id']
            event_time = entry_mod['transaction']['time']
            remote_address = entry_mod['transaction']['remote_address']
            request_line = entry_mod['request']['request_line']
            request_line_method, request_line_url, request_line_protocol = get_params(string_in=request_line, defaultmissing='-', params_to_get=3)
            request_headers_useragent = safedictkey(entry_mod, ['request','headers','User-Agent'], '-')
            request_headers_host = safedictkey(entry_mod, ['request','headers','Host'], '-')
            response_protocol = safedictkey(entry_mod, ['response', 'protocol'], '-')
            response_status = safedictkey(entry_mod, ['response','status'], '-')
            audit_data_producer = safedictkey(entry_mod, ['audit_data','producer'], '-')
            audit_data_server = safedictkey(entry_mod, ['audit_data', 'server'], '-')
            audit_data_enginemode = safedictkey(entry_mod, ['audit_data','Engine-Mode'], '-')
            audit_data_action_intercepted = 'intercepted' if (safedictkey(entry_mod, ['audit_data','action','intercepted'], '-') == True) else '-'
            audit_data_action_message = safedictkey(entry_mod, ['audit_data','action','message'], '-')
            audit_data_action_phase = safedictkey(entry_mod, ['audit_data','action','phase'], '-')

            if ('messages' in entry_mod['audit_data']) and (len(entry_mod['audit_data']) > 0):
                if len(entry_mod['audit_data']['messages']) > 1:
                    audit_data_message_type = 'multiple'
                else:
                    audit_data_message_type = 'single'
                for each in entry_mod['audit_data']['messages']:
                    audit_data_message_message = regular_expression_evaluate(each, modsec_message_message_pattern)
                    audit_data_message_file = regular_expression_evaluate(each, modsec_message_file_pattern, to_split=True, to_split_value='/', to_split_column=-1)
                    audit_data_message_id = regular_expression_evaluate(each, modsec_message_id_pattern)
                    audit_data_message_msg = regular_expression_evaluate(each, modsec_message_msg_pattern)
                    audit_data_message_severity = regular_expression_evaluate(each, modsec_message_severity_pattern)
                    audit_data_message_maturity = regular_expression_evaluate(each, modsec_message_maturity_pattern)
                    audit_data_message_accuracy = regular_expression_evaluate(each, modsec_message_accuracy_pattern)
                    #audit_data_message_tags = [] # TAGS not in use currently
                    ws1.append([transaction_id, event_time, remote_address, request_headers_host, request_headers_useragent,
                                request_line, request_line_method, request_line_url, request_line_protocol,
                                response_protocol, response_status,
                                audit_data_action_intercepted, audit_data_action_phase, audit_data_action_message,
                                audit_data_message_type,audit_data_message_message, audit_data_message_id, audit_data_message_file,
                                audit_data_message_msg, audit_data_message_severity, audit_data_message_accuracy, audit_data_message_maturity,
                                each
                                ])
            else:
                audit_data_message_type = 'None'
                each = 'None'
                #print('M error - message not found for transaction_id :', transaction_id)
                audit_data_message_message = audit_data_message_file = audit_data_message_id = audit_data_message_msg = \
                audit_data_message_severity = audit_data_message_maturity = audit_data_message_accuracy = '-'
                ws1.append([transaction_id, event_time, remote_address, request_headers_host, request_headers_useragent,
                            request_line, request_line_method, request_line_url, request_line_protocol,
                            response_protocol, response_status,
                            audit_data_action_intercepted, audit_data_action_phase, audit_data_action_message,
                            audit_data_message_type, audit_data_message_message, audit_data_message_id, audit_data_message_file,
                            audit_data_message_msg, audit_data_message_severity, audit_data_message_accuracy, audit_data_message_maturity,
                            each
                            ])
        except Exception as e:
            print('Exception at modsecSaveXLSX() :', e , ' , transaction_id :', transaction_id)

    if not 'error' in outputWithGraphs:
        img = openpyxl.drawing.image.Image(outputWithGraphs)
        ws2 = wb.create_sheet('Graphs')
        ws2.add_image(img)

    try:
        if not os.path.isdir(fileBaseOutputDir):
            os.mkdir(fileBaseOutputDir)
        fOut = os.path.join(fileBaseOutputDir, outputXLSXFileName)
        wb.save(filename=fOut)
    except Exception as e:
        print('modsecSaveXLSX() has thrown exception: %s', e)

    pass

def modsecViewGraphs(modsecDict):
    """
    Module to visualize audit log as graphs
    :param modsecDict: list of modsec_audit events given as a dictionary
    :return: png file output or string 'error' in case no valid image created
    """
    if len(modsecDict) < 1:
        exit('Error: No logs to visualize. Check log and Include/Exclude filters')
    '''
    GRAPHS PART I
    Collect information into lists/dicts to make particular graphs
    '''
    src_ip_tab = []
    event_time_action = []
    event_messages = []
    intercepted_reason = []
    event_rules = []
    for entry_mod in modsecDict:
        try:
            ''' Graph data for "TOP 10 IP source addresses" '''
            src_ip_tab.append(entry_mod['transaction']['remote_address'])

            ''' Graph data for "Modsecurity Events reported vs intercepted" '''
            if (version3 is False) and ('action' in entry_mod['audit_data'].keys() and 'intercepted' in entry_mod['audit_data']['action'].keys()):
                event_time_action.append([entry_mod['transaction']['time'], True])

            elif (version3 is True) and len(entry_mod['audit_data']) > 0:
                for each_msg in entry_mod['audit_data']['messages']:
                    #print('each_msg :', each_msg)
                    if each_msg.startswith("ModSecurity: Access denied"):
                        event_time_action.append([entry_mod['transaction']['time'], True])
                    else:
                        event_time_action.append([entry_mod['transaction']['time'], False])
                        #print('Nobody expect the Spanish Inquisition for ModSecurity v3')
                        #print('each_msg :', each_msg)
            else:
                # No 'intercepted'
                event_time_action.append([entry_mod['transaction']['time'], False])
        except Exception as e2:
            print('Exception in Graph TOP 10 IP source addresses', e2)

        ''' Graph data for "TOP 20 rule hits"'''
        try:
            if 'messages' in entry_mod['audit_data'].keys():
                messages = safedictkey(entry_mod, ['audit_data','messages'], '-')
                for each in messages:
                    event_messages.append(each)
                    rule_id = regular_expression_evaluate(each, modsec_message_id_pattern)
                    rule_msg = regular_expression_evaluate(each, modsec_message_msg_pattern)
                    rule_severity = regular_expression_evaluate(each, modsec_message_severity_pattern)
                    rule_file = regular_expression_evaluate(each, modsec_message_file_pattern)
                    """
                    Cut the [msg] to 27 chars if it is longer than 30 chars.
                    If [msg] and [id] not found then treat message description as the [msg]
                    """
                    if len(rule_msg) > 30:
                        rule_msg = rule_msg[:27] + '...'
                    if rule_msg == '?' and rule_id == '-':
                        rule_msg = str(each)[:30]
                    rule_descr = 'id: ' + str(rule_id) + ', sev: ' + str(rule_severity) + ', msg: ' + str(rule_msg)
                    event_rules.append([rule_id, rule_msg, rule_severity, rule_file, rule_descr])
            else:
                ''' Skip modsec_audit entries without [message] part'''
                pass
        except Exception as e3:
            print('Exception in TOP 20 rule hits', e3)
            print('for transaction_id :', safedictkey(entry_mod, ['transaction','transaction_id'], '-'))

        ''' Graph data for "TOP 10 Attacks intercepted" '''
        try:
            if (version3 is False) and ('action' in entry_mod['audit_data']):
                msg = entry_mod['audit_data']['action']['message']
                if len(msg) > 60:
                    msg = msg[:50] + '...'
                intercepted_reason.append([entry_mod['audit_data']['action']['phase'], msg, 'phase ' + str(entry_mod['audit_data']['action']['phase']) + ': ' + msg])
            elif (version3 is True) and len(entry_mod['audit_data']) > 0:
                for each_msg in entry_mod['audit_data']['messages']:
                    if each_msg.startswith("ModSecurity: Access denied"):
                        msg = regular_expression_evaluate(each_msg, modsec_v3_message_msg_pattern)
                        if len(msg) > 60:
                            msg = msg[:50] + '...'
                        phase = regular_expression_evaluate(each_msg, modsec_v3_message_phase_pattern)
                        intercepted_reason.append([phase, msg, 'phase ' + phase + ': ' + msg])

        except Exception as e:
            print('Exception in Graph TOP 10 Attacks intercepted', e)
    """
    Modsecurity events Passed vs Intercepted
    """
    np_event_time_action = np.array(event_time_action)
    event_times1 = np_event_time_action[:, 0]
    event_times = list(map(lambda x: datetime.strptime(x, LOG_TIMESTAMP_FORMAT).replace(tzinfo=None), event_times1))
    event_action = np_event_time_action[:, 1]
    event_times_min = min(event_times); event_times_max = max(event_times); event_times_range = event_times_max - event_times_min
    event_times_range_seconds = int(event_times_range.total_seconds())
    event_times_range_minutes = int(event_times_range.total_seconds() / 60)
    if event_times_range_minutes < 60:
        PERIODS = str(int(event_times_range_seconds / 1)) + 's'
    else:
        PERIODS = str(int(event_times_range_minutes / 30)) + 'min'
    events_df = pd.DataFrame({
        'date': pd.to_datetime(event_times),
        'action': event_action
    })
    intercepted = [] ; passed = []; passed_cnt2 = 0; intercepted_cnt2 = 0
    for row in events_df['action']:
        if (row == 'True'):
            intercepted.append(1); passed.append(0); intercepted_cnt2 += 1
        else:
            intercepted.append(0); passed.append(1); passed_cnt2 += 1
    events_df['intercepted'] = intercepted; events_df['passed'] = passed
    '''
    GRAPHS PART II
    '''
    ''' TOP 10 IP addresses Graph - data preparation '''
    ipaddr_cnt = Counter()
    for word in src_ip_tab:
        ipaddr_cnt[word] += 1
    ipaddr_cnt_top10 = dict(ipaddr_cnt.most_common(10))

    ''' TOP 10 Interception Reason - data preparation'''
    intercepted_cnt = Counter()
    for word in intercepted_reason:
        intercepted_cnt[word[2]] += 1
    intercepted_cnt_top10 = dict(intercepted_cnt.most_common(10))
    ''' TOP 20 Rule IDs hit - data preparation'''
    event_messages_ids = Counter()
    for word in event_rules:
        event_messages_ids[word[4]] += 1
    event_messages_ids_top20 = dict(event_messages_ids.most_common(20))

    ''' GRIDS VERSION BEGIN '''
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
        modsec_inc_exc_str = 'Filter INCLUDE active. Skipped the rest of ' + str(records_skipped_cnt) + \
                             ' events where source IP address NOT in: ' + str(filter_include_table)
    elif FILTER_EXCLUDE:
        modsec_inc_exc_str = 'Filter EXCLUDE active. Skipped the rest of ' + str(records_skipped_cnt) + \
            ' events where source IP address in: ' + str(filter_exclude_table)
    else:
        modsec_inc_exc_str = 'Filter INCLUDE/EXCLUDE non-active.'

    title_timespan = 'Analysis of ' + str(records_processed_cnt) + ' modsecurity events in timespan: ' + \
                   str(event_times_min.strftime("%Y-%m-%d_%H:%M")) + ' - ' + str(event_times_max.strftime("%Y-%m-%d_%H:%M")) + '\n'
    title_total = 'Total number of events found in logfile ' + str(records_total) + ' (output always trimmed to variable MAXEVENTS = ' + str(MAXEVENTS) + ' )\n'
    title_reported_intercepted = 'events passed: ' + str(passed_cnt2) + ' , events intercepted: ' + str(intercepted_cnt2)
    plot_title = title_timespan + title_total + modsec_inc_exc_str + '\n\n' + title_reported_intercepted
    if event_times_range_seconds < 1800:
        short_time_range_message = 'Creating timeline graph is not available for timespan ' + str(event_times_range_seconds) + ' seconds, skipping ...'
        plt.subplot(ax1)
        plt.text(0.5, 0.5, short_time_range_message, horizontalalignment='center', verticalalignment='center')
        plt.title(plot_title)
    else:
        ex = events_df.groupby(pd.Grouper(key='date', freq=PERIODS)).sum()
        ex.plot(ax=ax1, kind='bar', title=plot_title, stacked=True, color={'purple', 'red'}, fontsize=7, rot=45)

    ''' Bar chart "TOP 10 IP addresses" '''
    plt.subplot(ax21)
    patches, texts, autotexts = plt.pie(ipaddr_cnt_top10.values(), autopct='%1.1f%%', shadow=True, startangle=90,radius=1.0)
    plt.title(' TOP %s IP addresses (out of total %s) ' % (len(ipaddr_cnt_top10), len(ipaddr_cnt)), bbox={'facecolor': '0.8', 'pad': 5})

    ''' Legend for chart "TOP 10 IP addresses" '''
    x = np.char.array(list(ipaddr_cnt_top10.keys()))
    y = np.array(list(ipaddr_cnt_top10.values()))
    labels = ['{0} --> {1} hits'.format(i, j) for i, j in
              zip(ipaddr_cnt_top10.keys(), ipaddr_cnt_top10.values())]
    if len(ipaddr_cnt_top10.keys()) >= 1:
        patches, labels, dummy = zip(*sorted(zip(patches, labels, y), key=lambda x: x[2], reverse=True))
        plt.subplot(ax22)
        plt.axis('off')
        plt.legend(patches, labels, loc='center left', bbox_to_anchor=(-0.1, 1.), fontsize=7)

    ''' Bar chart "TOP 10 Attacks intercepted" '''
    plt.subplot(ax31)
    patches, texts, autotexts = plt.pie(intercepted_cnt_top10.values(), autopct='%1.1f%%', shadow=True, startangle=90, radius=1.0)
    [_.set_fontsize(7) for _ in texts]
    plt.title('TOP 10 Attacks intercepted', bbox={'facecolor': '0.8', 'pad': 5})

    ''' Legend for chart "TOP 10 Attacks intercepted" '''
    x = np.char.array(list(intercepted_cnt_top10.keys()))
    y = np.array(list(intercepted_cnt_top10.values()))
    labels = ['{0} --> {1} hits'.format(i,j) for i,j in zip(intercepted_cnt_top10.keys(), intercepted_cnt_top10.values())]
    if len(intercepted_cnt_top10.values()) >= 1:
        patches, labels, dummy = zip(*sorted(zip(patches, labels, y), key=lambda x: x[2], reverse=True))
        plt.subplot(ax32)
        plt.axis('off')
        plt.legend(patches, labels, loc='center left', bbox_to_anchor=(-0.1, 1.), fontsize=7)
    else:
        plt.subplot(ax32)
        plt.axis('off')
        plt.text(0.5, 0.5, 'No intercepted events found for given data set', horizontalalignment='center', verticalalignment='center')

    ''' Bar chart "TOP 20 Rule IDs hit" '''
    plt.subplot(ax41)
    patches, texts, autotexts = plt.pie(event_messages_ids_top20.values(), autopct='%1.1f%%', shadow=True, startangle=90, radius=1.0)
    plt.title('TOP 20 Rule IDs hit', bbox={'facecolor': '0.8', 'pad': 5})

    ''' Legend for chart "TOP 20 Rule IDs hit" '''
    x = np.char.array(list(event_messages_ids_top20.keys()))
    y = np.array(list(event_messages_ids_top20.values()))
    labels = ['{0} --> {1} hits'.format(i, j) for i, j in zip(event_messages_ids_top20.keys(), event_messages_ids_top20.values())]
    if len(event_messages_ids_top20.keys()) >= 1:
        patches, labels, dummy = zip(*sorted(zip(patches, labels, y), key=lambda x: x[2], reverse=True))
        plt.subplot(ax42, axis='off')
        plt.axis('off')
        plt.legend(patches, labels, loc='center left', bbox_to_anchor=(-0.1, 1.), fontsize=7)

    '''
    GRID VERSION END
    '''
    graph_title = 'Modsecurity events ' + str(datetimenow) + ' from file: ' + inputFileName + ' first ' + str(MAXEVENTS) + ' analyzed'
    fig.canvas.set_window_title(graph_title)
    fig.set_size_inches(18,11)
    #plt.get_current_fig_manager().window.wm_geometry("+10+10")
    try:
        if not os.path.isdir(fileBaseOutputDir):
            os.mkdir(fileBaseOutputDir)
        fOut = os.path.join(fileBaseOutputDir, graphOutputFilename)
        plt.savefig(fOut)
        return(fOut)
    except Exception as e:
        print('modsecViewGraphs.savefig() thrown exception: %s', e)
        return('error')

def modsecLog2Info(singleEntry):
    """
    Module gets piece of log for single modsecurity event and transform into dict (JSON) according to standard JSON logging
    :param text consisted of many lines for single modsecurity event.
            Expected it starting with section 'A' and ending with section 'Z'
    :return: dict type with modsec_audit entry converted into JSON
    """
    modsec_dict = OrderedDict()
    a_header = singleEntry[0]
    if version3:
        e_separator = a_header[a_header.find('^---')+ 4:a_header.find('---A--')]
    else:
        e_separator = a_header[a_header.find('^--')+3:a_header.find('-A-')]
    itemNumber = 0
    itemKV = OrderedDict()
    try:
        for item in singleEntry:
            if item.__contains__(e_separator):
                itemKV[item.rstrip()[-3:-2:]] = itemNumber
            itemNumber+=1
        item_keys = list(itemKV.keys())
        itemKVFull = OrderedDict()
        for item_letter in item_keys:
            if item_letter in modsec_event_types:
                i = int(itemKV[item_letter]) + 1
                j = itemKV[item_keys[item_keys.index(item_letter) + 1 ] ]
                itemKVFull[item_letter] = singleEntry[i:j]

        modsec_a = itemKVFull['A'][0]
        modsec_b = itemKVFull['B']
        modsec_f = itemKVFull['F']
        modsec_h = itemKVFull['H']

        modsec_b_headers = dict(map(lambda s: [s[0:s.find(': ')],s[s.find(': ')+2:]], modsec_b[1:-1]))
        modsec_f_headers = dict(map(lambda s: [s, '-'] if len(s.split(': ')) == 1 else [s[0:s.find(': ')], s[s.find(': ') + 2:]], modsec_f[1:-1]))

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
                    modsec_h_dict['action']['phase'] = int(elem[elem.find('phase')+6])
                    modsec_h_dict['action']['message'] = modsec_h_dict['messages'][-1].split('.')[1].strip()
            elif elem.startswith('Stopwatch2'):
                modsec_h_dict['stopwatch'] = {}
                for stopw in elem.split(' '):
                    if '=' in stopw:
                        modsec_h_dict['stopwatch'][stopw.split('=')[0]] = int(stopw.split('=')[1].strip(','))

            else:
                pass
        modsec_a_split = modsec_a.split()
        modsec_dict['transaction'] = {'time' : modsec_a_split[0].replace('[','') + ' ' + modsec_a_split[1].replace(']',''), 'transaction_id': modsec_a_split[2], 'remote_address' : modsec_a_split[3],
                                  'remote_port': modsec_a_split[4], 'local_address': modsec_a_split[5], 'local_port': modsec_a_split[6] }
        if len(modsec_b) > 0:
            modsec_dict['request'] = {'request_line': modsec_b[0], 'headers': modsec_b_headers}
        else:
            modsec_dict['request'] = 'None'

        if len(modsec_f_headers) > 3:
            modsec_dict['response'] = OrderedDict()
            try:
                modsec_dict['response'] = {'protocol': modsec_f[0].split(' ')[0], 'status': modsec_f[0].split(' ')[1], 'status_text': ' '.join(modsec_f[0].split(' ')[2:]), 'headers': modsec_f_headers}
            except Exception as e:
                print('Exception at modsec_dict["response"] :', e)
                modsec_dict['response'] = 'None'
        else:
            modsec_dict['response'] = 'None'
        modsec_dict['audit_data'] = OrderedDict()
        modsec_dict['audit_data'] = modsec_h_dict
    except Exception as e:
        print('modsecLog2Info() error found :', e, ' when processing :', singleEntry)
        modsec_dict = 'ERROR'

    return modsec_dict

def processModsecAudit(inputFileName):
    try:
        with open(inputFileName, 'r', encoding='cp437') as modsecFHandler:
            modsec_Table = []
            for logLine in modsecFHandler:
                if a_pattern.search(logLine):
                    modsec_Entry = [logLine]
                    for entryLog in modsecFHandler:
                        if z_pattern.search(entryLog):
                            modsec_Entry.append(entryLog.rstrip())
                            modsec_Table.append(modsec_Entry)
                            break
                        else:
                            modsec_Entry.append(entryLog.rstrip())
        return modsec_Table
    except FileNotFoundError:
        print('File "', inputFileName, '" not found')
        return 'error'
    except Exception as e:
        print('Error found during read file ', inputFileName)
        return 'error'

def processModsecAudit3(inputFileName):
    try:
        with open(inputFileName, 'r') as modsecFHandler:
            modsec_Table = []
            for logLine in modsecFHandler:
                p = json.loads(logLine)
                modsec_Table.append(p)
        return modsec_Table
    except FileNotFoundError:
        print('File "', inputFileName, '" not found')
        return 'error'
    except Exception as e:
        print('Error found during read file ', inputFileName)
        return 'error'

if __name__ == "__main__":
    if jsonaudit is True:
        modsec_Table = processModsecAudit3(inputFileName)
    else:
        modsec_Table = processModsecAudit(inputFileName)
    if isinstance(modsec_Table, str) and modsec_Table in 'error':
        print('No modsecurity audit log found')
    elif isinstance(modsec_Table, list) and len(modsec_Table) == 0:
        print('No modsecurity events found in the specified file')
    else:
        records_total = len(modsec_Table)
        modsec_entries = []
        for modsec_entry in modsec_Table:
            if jsonaudit is False:
                json_modsec_entry = modsecLog2Info(modsec_entry)
            else:
                json_modsec_entry = modsec_entry
            if FILTER_INCLUDE:
                if dict(json_modsec_entry)['transaction']['remote_address'] in filter_include_table:
                    modsec_entries.append(json_modsec_entry)
                    records_processed_cnt +=1
                else:
                    records_skipped_cnt +=1
            elif FILTER_EXCLUDE:
                if dict(json_modsec_entry)['transaction']['remote_address'] not in filter_exclude_table:
                    modsec_entries.append(json_modsec_entry)
                    records_processed_cnt +=1
                else:
                    records_skipped_cnt +=1
            elif (isinstance(json_modsec_entry, str)) and ('ERROR' in json_modsec_entry):
                records_skipped_cnt += 1
            else:
                modsec_entries.append(json_modsec_entry)
                records_processed_cnt +=1
            if records_processed_cnt >= MAXEVENTS:
                print('-' * 10, 'Limit ', MAXEVENTS, ' of events has been reached. ')
                print('-' * 10, 'The rest of ', str(records_total - MAXEVENTS - records_skipped_cnt), ' events will be skipped ...', '-' * 10)
                break
        print('-' * 10, 'modsec_audit events processed: %s   ' % records_processed_cnt, '-' * 10)
        print('-' * 10, 'modsec_audit events skipped by INCLUDED/EXCLUDED options or INVALID :', records_skipped_cnt, '-' * 10)
        if len(modsec_entries) < 1:
            print('ERROR : modsec_audit entries to analyze not found with used filters')
        else:
            modsecSaveJson(modsec_entries, jsonOutputFilename, JSON_ONE_PER_LINE)
            outputWithGraphs = modsecViewGraphs(modsec_entries)
            modsecSaveXLSX(modsec_entries, xlsxOutputFilename, outputWithGraphs)
