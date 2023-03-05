# flake8: noqa F401
# from typing import Any
# from typing import SupportsFloat

# import sys
# import os
# import path
# from modsecurity_parser import safedictkey  # noqa: E402, F401

from modsecurity_parser import get_params, safedictkey

import pytest


def test_safedictkey():
    dict = {'audit_data': {"server": "Nginx"}}
    keyname = ['audit_data', 'server']
    assert safedictkey(dict, keyname, '-') == "Nginx"


def test_get_params():
    string_in = 'GET /verifylogin.do HTTP/1.1'
    separator = ' '
    default_missing = '-'
    params_to_get = 3
    output = ['GET', '/verifylogin.do', 'HTTP/1.1']
    # assert get_params(string_in, separator, default_missing, params_to_get) == set([output[1], output[0], output[2]])
    assert get_params(string_in, separator, default_missing, params_to_get)[0] == output[0]
    assert get_params(string_in, separator, default_missing, params_to_get)[1] == output[1]
    assert get_params(string_in, separator, default_missing, params_to_get)[2] == output[2]


def test_regular_expression_evaluate():
    pass


def test_modsec_save_json():
    pass


def test_modsec_save_xlsx():
    pass


def test_modsec_view_graphs():
    pass


def test_modsec_log_to_info():
    pass


def test_process_modsec_audit_std():
    pass


def test_process_modsec_audit_json():
    pass


def test_all_params():
    pass
