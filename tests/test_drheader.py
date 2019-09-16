#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Tests for `drheader` package."""
import json
import os
from operator import itemgetter

import pytest

from drheader import Drheader


def test_get_headers_ok():
    url = 'https://example.com'
    drheader_instance = Drheader(url=url)
    drheader_instance.analyze()
    assert drheader_instance.report is not None


def test_compare_rules_ok():
    with open(os.path.join(os.path.dirname(__file__), 'testfiles/header_ok.json'), 'r') as f:
        file = json.loads(f.read())

    drheader_instance = Drheader(headers=file, status_code=200)
    drheader_instance.analyze()
    assert len(drheader_instance.report) == 0


def test_compare_rules_enforce_ko():
    headers = {'X-XSS-Protection': '1; mode=bloc',
               'Content-Security-Policy': "default-src 'none'; script-src 'self'; object-src 'self';"}
    drheader_instance = Drheader(headers=headers, status_code=200)
    drheader_instance.analyze()
    assert {'severity': 'high', 'rule': 'X-XSS-Protection', 'message': 'Value does not match security policy',
            'expected': ['1', 'mode=block'], 'delimiter': ';', 'value': '1; mode=bloc'} in drheader_instance.report


def test_compare_rules_required_ko():
    headers = {'X-XSS-Protection': '1; mode=block'}
    drheader_instance = Drheader(headers=headers, status_code=200)
    drheader_instance.analyze()
    assert {'severity': 'high', 'rule': 'Content-Security-Policy',
            'message': 'Header not included in response'} in drheader_instance.report


def test_compare_rules_not_required_ko():
    headers = {'X-XSS-Protection': '1; mode=block',
               'Content-Security-Policy': "default-src 'none'; script-src 'self'; object-src 'self';",
               'Server': 'Apache',
               'X-Generator': 'Drupal 7 (http://drupal.org)'}
    drheader_instance = Drheader(headers=headers, status_code=200)

    drheader_instance.analyze()
    assert {'severity': 'high', 'rule': 'Server',
            'message': 'Header should not be returned'} in drheader_instance.report
    assert {'severity': 'high', 'rule': 'X-Generator',
            'message': 'Header should not be returned'} in drheader_instance.report


def test_compare_must_contain_ko():
    headers = {'X-XSS-Protection': '1; mode=block',
               'Content-Security-Policy': "default-src 'random'; script-src 'self'"}
    drheader_instance = Drheader(headers=headers, status_code=200)

    drheader_instance.analyze()
    assert {'severity': 'high', 'rule': 'Content-Security-Policy',
            'message': 'Must-Contain directive missed',
            'expected': ["default-src 'none'", "default-src 'self'"],
            'delimiter': ';',
            'value': "default-src 'random'; script-src 'self'",
            'anomaly': ["default-src 'none'", "default-src 'self'"]} in drheader_instance.report


def test_compare_must_avoid_ko():
    headers = {'X-XSS-Protection': '1; mode=block',
               'Content-Security-Policy': "default-src 'none'; script-src 'self'; object-src 'self'; "
                                          "unsafe-inline 'self;"}
    drheader_instance = Drheader(headers=headers, status_code=200)
    drheader_instance.analyze()
    assert {'severity': 'medium', 'rule': 'Content-Security-Policy',
            'message': 'Must-Avoid directive included', 'expected': ['unsafe-inline', 'unsafe-eval'], 'delimiter': ';',
            'value': "default-src 'none'; script-src 'self'; object-src 'self'; unsafe-inline 'self;",
            'anomaly': 'unsafe-inline'} in drheader_instance.report


def test_compare_optional():
    headers = {'X-XSS-Protection': '1; mode=block', 'Set-Cookie': ['Test']}
    drheader_instance = Drheader(headers=headers, status_code=200)
    drheader_instance.analyze()
    assert {'severity': 'medium', 'rule': 'Set-Cookie',
            'message': 'Must-Contain directive missed',
            'expected': ['HttpOnly', 'Secure'], 'value': 'Test',
            'delimiter': ';',
            'anomaly': 'HttpOnly'} in drheader_instance.report
    assert {'severity': 'high', 'rule': 'Set-Cookie',
            'message': 'Must-Contain directive missed', 'expected': ['HttpOnly', 'Secure'], 'delimiter': ';',
            'value': 'Test',
            'anomaly': 'Secure'} in drheader_instance.report


def test_compare_optional_not_exist():
    headers = {'X-XSS-Protection': '1; mode=block'}
    drheader_instance = Drheader(headers=headers, status_code=200)
    drheader_instance.analyze()
    assert {'severity': 'medium ', 'rule': 'Set-Cookie',
            'message': 'Must-Contain directive missed', 'expected': ['HttpOnly', 'Secure'],
            'value': 'Test',
            'anomaly': 'HttpOnly'} not in drheader_instance.report
    assert {'severity': 'medium', 'rule': 'Set-Cookie',
            'message': 'Must-Contain directive missed', 'expected': ['HttpOnly', 'Secure'],
            'value': 'Test',
            'anomaly': 'Secure'} not in drheader_instance.report


def test_referrer_policy_invalid_value():
    headers = {'Referrer-Policy': 'origin'}
    drheader_instance = Drheader(headers=headers)
    drheader_instance.analyze()

    assert {'severity': 'high', 'rule': 'Referrer-Policy', 'message': 'Value does not match security policy',
            'expected':
                ['strict-origin', 'strict-origin-when-cross-origin', 'no-referrer'], 'delimiter': ',',
            'value': 'origin'} in drheader_instance.report


def test_referrer_policy_valid_values():
    headers = {'Referrer-Policy': 'no-referrer'}
    drheader_instance = Drheader(headers=headers)
    drheader_instance.analyze()
    assert {'severity': 'high', 'rule': 'Referrer-Policy', 'message': 'Value does not match security policy',
            'expected': ['strict-origin', 'strict-origin-when-cross-origin', 'no-referrer'],
            'value': 'no-referrer'} not in drheader_instance.report

    drheader_instance.headers = {'Referrer-Policy': 'strict-origin'}
    drheader_instance.analyze()

    assert {'severity': 'high', 'rule': 'Referrer-Policy', 'message': 'value does not match security policy',
            'expected': ['strict-origin', 'strict-origin-when-cross-origin', 'no-referrer'], 'delimiter': ',',
            'value': 'strict-origin'} not in drheader_instance.report
    drheader_instance.headers = {'Referrer-Policy': 'strict-origin-when-cross-origin'}
    drheader_instance.analyze()
    assert {'severity': 'high', 'rule': 'Referrer-Policy', 'message': 'Value does not match security policy',
            'expected': ['strict-origin', 'strict-origin-when-cross-origin', 'no-referrer'], 'delimiter': ';', 'value':
                'strict-origin-when-cross-origin'} not in drheader_instance.report


def test_csp_invalid_default_directive():
    headers = {'Content-Security-Policy': "default-src 'random';"}
    drheader_instance = Drheader(headers=headers, status_code=200)
    drheader_instance.analyze()
    assert {'severity': 'high', 'rule': 'Content-Security-Policy',
            'message': 'Must-Contain directive missed',
            'expected': ["default-src 'none'", "default-src 'self'"],
            'delimiter': ';',
            'value': "default-src 'random';",
            'anomaly': ["default-src 'none'", "default-src 'self'"]} in drheader_instance.report


def test_csp_valid_default_directive():
    headers = {'Content-Security-Policy': "default-src 'none';"}
    drheader_instance = Drheader(headers=headers, status_code=200)
    drheader_instance.analyze()
    assert {'severity': 'high', 'rule': 'Content-Security-Policy',
            'message': 'Must-Contain directive missed',
            'expected': ["default-src 'none'", "default-src 'self'"],
            'delimiter': ';',
            'value': "default-src 'none';",
            'anomaly': ["default-src 'none'", "default-src 'self'"]} not in drheader_instance.report
    drheader_instance.headers = {'Content-Security-Policy': "default-src 'self';"}
    drheader_instance.analyze()
    assert {'severity': 'high', 'rule': 'Content-Security-Policy',
            'message': 'Must-Contain directive missed',
            'expected': ["default-src 'none'", "default-src 'self'"],
            'delimiter': ';',
            'value': "default-src 'self';",
            'anomaly': ["default-src 'none'", "default-src 'self'"]} not in drheader_instance.report


def test_compare_rules_full_ko():
    headers = {'Server': 'Apache', 'X-Generator': 'Drupal 7 (http://drupal.org)',
               'X-XSS-Protection': '1; mode=bloc', 'Content-Security-Policy':
                   "default-src 'random'; script-sr 'self'; object-src 'self'; unsafe-inline 'self;"}
    drheader_instance = Drheader(headers=headers, status_code=200)
    expected = [
        {'severity': 'high',
         'rule': 'Content-Security-Policy',
         'message': 'Must-Contain directive missed',
         'expected': ["default-src 'none'", "default-src 'self'"],
         'delimiter': ';',
         'value': "default-src 'random'; script-sr 'self'; object-src 'self'; unsafe-inline 'self;",
         'anomaly': ["default-src 'none'", "default-src 'self'"]
         },
        {'severity': 'medium',
         'rule': 'Content-Security-Policy',
         'message': 'Must-Avoid directive included',
         'expected': ['unsafe-inline', 'unsafe-eval'],
         'delimiter': ';',
         'value': "default-src 'random'; script-sr 'self'; object-src 'self'; unsafe-inline 'self;",
         'anomaly': 'unsafe-inline'
         },
        {'severity': 'high', 'rule': 'X-XSS-Protection',
         'message': 'Value does not match security policy',
         'expected': ['1', 'mode=block'],
         'delimiter': ';',
         'value': '1; mode=bloc'
         },
        {'severity': 'high',
         'rule': 'Server',
         'message': 'Header should not be returned'
         },
        {'severity': 'high',
         'rule': 'Strict-Transport-Security',
         'message': 'Header not included in response',
         'expected': ['max-age=31536000', 'includeSubDomains'],
         'delimiter': ';'
         },
        {'severity': 'high',

         'rule': 'X-Frame-Options',
         'message': 'Header not included in response',
         'expected': ['SAMEORIGIN', 'DENY'],
         'delimiter': ';'
         },
        {'severity': 'high',
         'rule': 'X-Content-Type-Options',
         'message': 'Header not included in response',
         'expected': ['nosniff'],
         'delimiter': ';'
         },

        {'message': 'Header not included in response',
         'rule': 'Set-Cookie',
         'severity': 'high',
         },

        {'severity': 'high',
         'rule': 'Referrer-Policy',
         'message': 'Header not included in response',
         'expected': ['strict-origin', 'strict-origin-when-cross-origin', 'no-referrer'],
         'delimiter': ','
         },
        {'severity': 'high',
         'rule': 'Cache-Control',
         'message': 'Header not included in response',
         # modified this to account for list value rather then string
         'expected': ['no-cache', 'no-store', 'must-revalidate'],
         'delimiter': ','
         },
        {'severity': 'high',
         'rule': 'Pragma',
         'message': 'Header not included in response',
         'expected': ['no-cache'],
         'delimiter': ';'},
        {'severity': 'high',
         'rule': 'X-Generator',
         'message': 'Header should not be returned'
         }]

    drheader_instance.analyze()

    report, expected = [sorted(l, key=itemgetter('rule')) for l in (drheader_instance.report, expected)]

    assert not any(x != y for x, y in zip(report, expected))

# def test_command_line_interface():
#     """Test the CLI."""
#     runner = CliRunner()
#     result = runner.invoke(cli.main)
#     # assert result.exit_code == 0
#     # assert 'drheader.cli.main' in result.output
#     help_result = runner.invoke(cli.main,
#                                 ['-t', 'url'])
#     print(help_result.output)
#     # assert help_result.exit_code == 0
#     # assert '--help  Show this message and exit.' in help_result.output
