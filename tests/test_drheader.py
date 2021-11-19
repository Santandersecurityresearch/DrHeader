#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Tests for `drheader` package."""
import json
import logging
import os
import re

import unittest2
import yaml

from drheader import Drheader


class DrheaderRules(unittest2.TestCase):
    def setUp(self):
        # this is run each time before each test_ method is invoked
        self.logger = logging.Logger
        self.instance = ''
        self.report = list

        # configuration

    def tearDown(self):
        with open(os.path.join(os.path.dirname(__file__), 'testfiles/test_rules.yml'), 'w') as f_test,\
             open(os.path.join(os.path.dirname(__file__), 'testfiles/default_rules.yml')) as f_default:
            default_rules = yaml.safe_load(f_default.read())
            yaml.dump(default_rules, f_test, sort_keys=False)

    def _process_test(self, url=None, headers=None, status_code=None):
        # all tests use this method to run the test and analyze the results.
        with open(os.path.join(os.path.dirname(__file__), 'testfiles/test_rules.yml'), 'r') as f:
            rules = yaml.safe_load(f.read())['Headers']

        self.instance = Drheader(url=url, headers=headers, status_code=status_code)
        self.instance.analyze(rules=rules)

        # test can then make assertions against the contents of self.instance.report to determine success of failure.

    def test_get_headers_ok(self):
        url = 'https://google.com'
        self._process_test(url=url)
        self.assertNotEqual(self.report, None, msg="A Report was generated")

    def test_compare_rules_ok(self):
        with open(os.path.join(os.path.dirname(__file__), 'testfiles/header_ok.json'), 'r') as f:
            file = json.loads(f.read())

        self._process_test(headers=file, status_code=200)
        self.assertEqual(len(self.instance.report), 0, msg=self.build_error_message(self.instance.report))

    def test_compare_rules_ok_with_case_insensitive_keys(self):
        with open(os.path.join(os.path.dirname(__file__), 'testfiles/header_ok.json'), 'r') as f:
            file = json.loads(f.read())

        file['x-xss-protection'] = file.pop('X-XSS-Protection')

        self._process_test(headers=file, status_code=200)
        self.assertEqual(len(self.instance.report), 0, msg=self.build_error_message(self.instance.report))

    def test_compare_rules_ok_with_case_insensitive_values(self):
        with open(os.path.join(os.path.dirname(__file__), 'testfiles/header_ok.json'), 'r') as f:
            file = json.loads(f.read())

        file['Content-Security-Policy'] = file.pop('Content-Security-Policy').upper()
        file['X-Frame-Options'] = file.pop('X-Frame-Options').lower()

        self._process_test(headers=file, status_code=200)
        self.assertEqual(len(self.instance.report), 0, msg=self.build_error_message(self.instance.report))

    def test_compare_rules_enforce_ko(self):
        headers = {
            'X-XSS-Protection': '1; mode=bloc',
            'Content-Security-Policy': "default-src 'none'; script-src 'self'; object-src 'self';"
        }
        expected_response = {
            'severity': 'high',
            'rule': 'X-XSS-Protection',
            'message': 'Value does not match security policy',
            'expected': ['0'],
            'delimiter': ';',
            'value': '1; mode=bloc'
        }

        self._process_test(headers=headers, status_code=200)
        self.assertIn(expected_response, self.instance.report, msg="X-XSS")

    def test_compare_rules_required_ko(self):
        headers = {
            'X-XSS-Protection': '1; mode=block'
        }
        expected_response = {
            'severity': 'high',
            'rule': 'Content-Security-Policy',
            'message': 'Header not included in response'
        }

        self._process_test(headers=headers, status_code=200)
        self.assertIn(expected_response, self.instance.report, msg="Generated Rules")

    def test_compare_rules_not_required_ko(self):
        headers = {
            'X-XSS-Protection': '1; mode=block',
            'Content-Security-Policy': "default-src 'none'; script-src 'self'; object-src 'self';",
            'Server': 'Apache',
            'X-Generator': 'Drupal 7 (http://drupal.org)'
        }
        server_response = {
            'severity': 'high',
            'rule': 'Server',
            'message': 'Header should not be returned'
        }
        generator_response = {
            'severity': 'high',
            'rule': 'X-Generator',
            'message': 'Header should not be returned'
        }

        self._process_test(headers=headers, status_code=200)
        self.assertIn(server_response, self.instance.report, msg="Server Rule was triggered")
        self.assertIn(generator_response, self.instance.report, msg="Generator Rule was triggered")

    def test_compare_must_contain_ko(self):
        headers = {
            'X-XSS-Protection': '1; mode=block',
            'Content-Security-Policy': "default-src 'random'; script-src 'self'"
        }
        csp_contain_response = {
            'severity': 'high',
            'rule': 'Content-Security-Policy',
            'message': 'Must-Contain-One directive missed',
            'expected': ["default-src 'none'", "default-src 'self'"],
            'delimiter': ';',
            'value': "default-src 'random'; script-src 'self'",
            'anomaly': ["default-src 'none'", "default-src 'self'"]
        }

        self._process_test(headers=headers, status_code=200)
        self.assertIn(csp_contain_response, self.instance.report, msg="CSP Contain Rule was triggered")

    def test_compare_must_avoid_ko(self):
        headers = {
            'X-XSS-Protection': '1; mode=block',
            'Content-Security-Policy': "default-src 'none'; script-src 'self'; object-src 'self'; "
                                       "connect-src 'unsafe-inline';"
        }
        csp_avoid_response = {
            'severity': 'medium',
            'rule': 'Content-Security-Policy - connect-src',
            'message': 'Must-Avoid directive included',
            'avoid': ['unsafe-inline', 'unsafe-eval'], 'delimiter': ';',
            'value': "unsafe-inline",
            'anomaly': 'unsafe-inline'
        }

        self._process_test(headers=headers, status_code=200)
        self.assertIn(csp_avoid_response, self.instance.report, msg="CSP Avoid Rule was triggered")

    def test_compare_optional(self):
        headers = {
            'X-XSS-Protection': '0',
            'Set-Cookie': ['Test']
        }
        medium_contain_response = {
            'severity': 'medium',
            'rule': 'Set-Cookie',
            'message': 'Must-Contain directive missed',
            'expected': ['httponly', 'secure'],
            'value': 'test',
            'delimiter': ';',
            'anomaly': 'httponly'
        }
        high_contain_response = {
            'severity': 'high',
            'rule': 'Set-Cookie',
            'message': 'Must-Contain directive missed',
            'expected': ['httponly', 'secure'],
            'delimiter': ';',
            'value': 'test',
            'anomaly': 'secure'
        }

        self._process_test(headers=headers, status_code=200)
        self.assertIn(medium_contain_response, self.instance.report, msg="Medium Rule was triggered")
        self.assertIn(high_contain_response, self.instance.report, msg="High Rule was triggered")

    def test_compare_optional_not_exist(self):
        headers = {
            'X-XSS-Protection': '1; mode=block'
        }
        header_not_included_response = {
            'rule': 'Set-Cookie',
            'severity': 'high',
            'message': 'Header not included in response',
        }

        self._process_test(headers=headers, status_code=200)
        self.assertNotIn(header_not_included_response, self.instance.report, msg="Httponly Rule was triggered")

    def test_referrer_policy_invalid_values(self):
        headers = {
            'Referrer-Policy': 'origin'
        }
        referrer_response = {
            'severity': 'high',
            'rule': 'Referrer-Policy',
            'message': 'Must-Contain-One directive missed',
            'expected': ['strict-origin', 'strict-origin-when-cross-origin', 'no-referrer'],
            'delimiter': ',',
            'value': 'origin',
            'anomaly': ['strict-origin', 'strict-origin-when-cross-origin', 'no-referrer']
        }

        self._process_test(headers=headers)
        self.assertIn(referrer_response, self.instance.report, msg="Referrer Policy Rule was triggered")

    def test_referrer_policy_valid_values(self):
        headers = {
            'Referrer-Policy': 'no-referrer'
        }

        # this need updating as there is no referrer-policy rule in the output
        no_referrer_response = {
            'severity': 'high',
            'rule': 'Referrer-Policy',
            'message': 'Must-Contain-One directive missed',
            'expected': ['strict-origin', 'strict-origin-when-cross-origin', 'no-referrer'],
            'delimiter': ',',
            'value': 'no-referrer',
            'anomaly': ['strict-origin', 'strict-origin-when-cross-origin', 'no-referrer']
        }

        self._process_test(headers=headers)
        self.assertNotIn(no_referrer_response, self.instance.report, msg="No Referrer Policy Rule was triggered")

    def test_referrer_policy_invalid_values_typo(self):
        headers = {
            'Referrer-Policy': 'no-referrerr'
        }

        # this need updating as there is no referrer-policy rule in the output
        no_referrer_response = {
            'severity': 'high',
            'rule': 'Referrer-Policy',
            'message': 'Value does not match security policy',
            'expected': ['strict-origin', 'strict-origin-when-cross-origin', 'no-referrer'],
            'value': 'no-referrerr'
        }

        self._process_test(headers=headers)
        self.assertNotIn(no_referrer_response, self.instance.report, msg="No Referrer Policy Rule was triggered")

    def test_referrer_policy_strict_origin(self):
        headers = {
            'Referrer-Policy': 'strict-origin'
        }

        # this needs updating because there is no refferer policy in output
        no_referrer_response = {
            'severity': 'high',
            'rule': 'Referrer-Policy',
            'message': 'value does not match security policy',
            'expected': ['strict-origin', 'strict-origin-when-cross-origin', 'no-referrer'],
            'delimiter': ',',
            'value': 'strict-origin'
        }

        self._process_test(headers=headers)
        self.assertNotIn(no_referrer_response, self.instance.report, msg="Referrer SO Policy Rule was triggered")

    def test_referrer_policy_strict_cross_origin(self):
        headers = {
            'Referrer-Policy': 'strict-origin-when-cross-origin'
        }

        # this needs updating because there is no refferer policy in output
        referrer_strict_origin_response = {
            'severity': 'high',
            'rule': 'Referrer-Policy',
            'message': 'Value does not match security policy',
            'expected': ['strict-origin', 'strict-origin-when-cross-origin', 'no-referrer'],
            'delimiter': ';', 'value':
                'strict-origin-when-cross-origin'
        }

        self._process_test(headers=headers)
        self.assertNotIn(referrer_strict_origin_response, self.instance.report,
                         msg="Refered SOWCO Policy Rule was triggred")

    def test_csp_invalid_default_directive(self):
        headers = {
            'Content-Security-Policy': "default-src 'random';"
        }

        # this needs updating because there is no Content-Security-Warining in output
        csp_invalid_default_response = {
            'severity': 'high',
            'rule': 'Content-Security-Policy',
            'message': 'Must-Contain-One directive missed',
            'expected': ["default-src 'none'", "default-src 'self'"],
            'delimiter': ';',
            'value': "default-src 'random';",
            'anomaly': ["default-src 'none'", "default-src 'self'"]
        }

        self._process_test(headers=headers, status_code=200)
        self.assertIn(csp_invalid_default_response, self.instance.report, msg="CSP directive Policy Rule was triggered")

    def test_csp_valid_default_directive_none(self):
        headers = {
            'Content-Security-Policy': "default-src 'none';"
        }

        # this needs updating because there is no Content-Security-Warining in output
        csp_response_none = {
            'severity': 'high',
            'rule': 'Content-Security-Policy',
            'message': 'Must-Contain directive missed',
            'expected': ["default-src 'none'", "default-src 'self'"],
            'delimiter': ';',
            'value': "default-src 'none';",
            'anomaly': ["default-src 'none'", "default-src 'self'"]
        }

        self._process_test(headers=headers, status_code=200)
        self.assertNotIn(csp_response_none, self.instance.report, msg="CSP directive policy none was caught")

    def test_csp_invalid_default_directive_none(self):
        headers = {
            'Content-Security-Policy': "default-src 'non';"
        }

        # this needs updating because there is no Content-Security-Warining in output
        csp_response_none = {
            'severity': 'high',
            'rule': 'Content-Security-Policy',
            'message': 'Must-Contain-One directive missed',
            'expected': ["default-src 'none'", "default-src 'self'"],
            'delimiter': ';',
            'value': "default-src 'non';",
            'anomaly': ["default-src 'none'", "default-src 'self'"]
        }

        self._process_test(headers=headers, status_code=200)
        self.assertIn(csp_response_none, self.instance.report, msg="CSP directive policy none was caught")

    def test_csp_valid_default_directive_self(self):
        headers = {
            'Content-Security-Policy': "default-src 'self';"
        }
        csp_response_self = {
            'severity': 'high',
            'rule': 'Content-Security-Policy',
            'message': 'Must-Contain-One directive missed',
            'expected': ["default-src 'none'", "default-src 'self'"],
            'delimiter': ';',
            'value': "default-src 'self';",
            'anomaly': ["default-src 'none'", "default-src 'self'"]
        }

        self._process_test(headers=headers, status_code=200)
        self.assertNotIn(csp_response_self, self.instance.report, msg="CSP directive policy self was caught")

    def test_csp_invalid_default_directive_self(self):
        headers = {
            'Content-Security-Policy': "default-src 'selfie';"
        }
        csp_response_self = {
            'severity': 'high',
            'rule': 'Content-Security-Policy',
            'message': 'Must-Contain-One directive missed',
            'expected': ["default-src 'none'", "default-src 'self'"],
            'delimiter': ';',
            'value': "default-src 'selfie';",
            'anomaly': ["default-src 'none'", "default-src 'self'"]
        }

        self._process_test(headers=headers, status_code=200)
        self.assertIn(csp_response_self, self.instance.report, msg="CSP directive policy self was caught")

    def test_compare_rules_full_output(self):
        headers = {
            'Server': 'Apache',
            'X-Generator': 'Drupal 7 (http://drupal.org)',
            'X-XSS-Protection': '1; mode=bloc',
            'Content-Security-Policy': "default-src 'random'; script-src 'self'; object-src 'self'; "
                                       "connect-src 'unsafe-inline';"
        }
        expected_report = [
            {
                'severity': 'high',
                'rule': 'Content-Security-Policy',
                'message': 'Must-Contain-One directive missed',
                'expected': ["default-src 'none'", "default-src 'self'"],
                'delimiter': ';',
                'value': "default-src 'random'; script-src 'self'; object-src 'self'; connect-src 'unsafe-inline';",
                'anomaly': ["default-src 'none'", "default-src 'self'"]
            },
            {
                'severity': 'medium',
                'rule': 'Content-Security-Policy - connect-src',
                'message': 'Must-Avoid directive included',
                'avoid': ['unsafe-inline', 'unsafe-eval'],
                'delimiter': ';',
                'value': "unsafe-inline",
                'anomaly': 'unsafe-inline'
            },
            {
                'severity': 'high', 'rule': 'X-XSS-Protection',
                'message': 'Value does not match security policy',
                'expected': ['0'],
                'delimiter': ';',
                'value': '1; mode=bloc'
            },
            {
                'severity': 'high',
                'rule': 'Server',
                'message': 'Header should not be returned'
            },
            {
                'severity': 'high',
                'rule': 'Strict-Transport-Security',
                'message': 'Header not included in response',
                'expected': ['max-age=31536000', 'includesubdomains'],
                'delimiter': ';'
            },
            {
                'severity': 'high',
                'rule': 'X-Frame-Options',
                'message': 'Header not included in response',
                'expected': ['sameorigin', 'deny'],
                'delimiter': ';'
            },
            {
                'severity': 'high',
                'rule': 'X-Content-Type-Options',
                'message': 'Header not included in response',
                'expected': ['nosniff'],
                'delimiter': ';'
            },
            {
                'severity': 'high',
                'rule': 'Referrer-Policy',
                'message': 'Header not included in response'
            },
            {
                'severity': 'high',
                'rule': 'Cache-Control',
                'message': 'Header not included in response',
                'expected': ['no-store', 'max-age=0'],
                'delimiter': ','
            },
            {
                'severity': 'high',
                'rule': 'Pragma',
                'message': 'Header not included in response',
                'expected': ['no-cache'],
                'delimiter': ';'
            },
            {
                'severity': 'high',
                'rule': 'X-Generator',
                'message': 'Header should not be returned'
            }
        ]

        self._process_test(headers=headers, status_code=200)
        self.assertEqual(self.instance.report, expected_report, msg=self.build_error_message(self.instance.report, expected_report))

    def test_csp_required_directive_not_present(self):
        with open(os.path.join(os.path.dirname(__file__), 'testfiles/header_ok.json'), 'r') as f_headers,\
             open(os.path.join(os.path.dirname(__file__), 'testfiles/test_rules.yml'), 'r') as f_rules:
            headers = json.loads(f_headers.read())
            rules = yaml.safe_load(f_rules.read())

        rule_value = rules['Headers']['Content-Security-Policy']
        rule_value['Directives'] = {
            'script-src': {
                'Required': True,
                'Enforce': False
            }
        }
        self.modify_rules('Content-Security-Policy', rule_value)

        directive = re.search('script-src [^;]*(;)?', headers['Content-Security-Policy']).group()
        headers['Content-Security-Policy'] = headers['Content-Security-Policy'].replace(directive, '')

        expected_report = {
            'severity': 'high',
            'rule': 'Content-Security-Policy - script-src',
            'message': 'Directive not included in response'
        }
        self._process_test(headers=headers, status_code=200)
        self.assertIn(expected_report, self.instance.report)

    def test_csp_directive_invalid_value(self):
        with open(os.path.join(os.path.dirname(__file__), 'testfiles/header_ok.json'), 'r') as f_headers,\
             open(os.path.join(os.path.dirname(__file__), 'testfiles/test_rules.yml'), 'r') as f_rules:
            headers = json.loads(f_headers.read())
            rules = yaml.safe_load(f_rules.read())

        rule_value = rules['Headers']['Content-Security-Policy']
        rule_value['Directives'] = {
            'script-src': {
                'Required': True,
                'Enforce': True,
                'Delimiter': ' ',
                'Value': ['self']
            }
        }
        self.modify_rules('Content-Security-Policy', rule_value)

        directive = re.search('script-src [^;]*(;)?', headers['Content-Security-Policy']).group()
        headers['Content-Security-Policy'] = headers['Content-Security-Policy'].replace(directive, 'script-src https://www.santander.co.uk https://www.google.com;')

        expected_report = {
            'severity': 'high',
            'rule': 'Content-Security-Policy - script-src',
            'message': 'Value does not match security policy',
            'expected': ['self'],
            'delimiter': ' ',
            'value': 'https://www.santander.co.uk https://www.google.com'
        }
        self._process_test(headers=headers, status_code=200)
        self.assertIn(expected_report, self.instance.report)

    def test_csp_directive_must_avoid_value_included(self):
        with open(os.path.join(os.path.dirname(__file__), 'testfiles/header_ok.json'), 'r') as f_headers,\
             open(os.path.join(os.path.dirname(__file__), 'testfiles/test_rules.yml'), 'r') as f_rules:
            headers = json.loads(f_headers.read())
            rules = yaml.safe_load(f_rules.read())

        rule_value = rules['Headers']['Content-Security-Policy']
        rule_value['Directives'] = {
            'script-src': {
                'Required': True,
                'Enforce': False,
                'Delimiter': ' ',
                'Value': '',
                'Must-Avoid': ['https://www.santander.co.uk']
            }
        }
        self.modify_rules('Content-Security-Policy', rule_value)

        directive = re.search('script-src [^;]*(;)?', headers['Content-Security-Policy']).group()
        headers['Content-Security-Policy'] = headers['Content-Security-Policy'].replace(directive, 'script-src https://www.santander.co.uk https://www.google.com;')

        expected_report = {
            'severity': 'medium',
            'rule': 'Content-Security-Policy - script-src',
            'message': 'Must-Avoid directive included',
            'avoid': ['https://www.santander.co.uk'],
            'delimiter': ' ',
            'value': 'https://www.santander.co.uk https://www.google.com',
            'anomaly': 'https://www.santander.co.uk'
        }
        self._process_test(headers=headers, status_code=200)
        self.assertIn(expected_report, self.instance.report)

    def test_csp_directive_must_contain_value_not_included(self):
        with open(os.path.join(os.path.dirname(__file__), 'testfiles/header_ok.json'), 'r') as f_headers,\
             open(os.path.join(os.path.dirname(__file__), 'testfiles/test_rules.yml'), 'r') as f_rules:
            headers = json.loads(f_headers.read())
            rules = yaml.safe_load(f_rules.read())

        rule_value = rules['Headers']['Content-Security-Policy']
        rule_value['Directives'] = {
            'script-src': {
                'Required': True,
                'Enforce': False,
                'Delimiter': ' ',
                'Value': '',
                'Must-Contain': ['https://www.santander.co.uk']
            }
        }
        self.modify_rules('Content-Security-Policy', rule_value)

        directive = re.search('script-src [^;]*(;)?', headers['Content-Security-Policy']).group()
        headers['Content-Security-Policy'] = headers['Content-Security-Policy'].replace(directive, 'script-src \'self\';')

        expected_report = {
            'severity': 'medium',
            'rule': 'Content-Security-Policy - script-src',
            'message': 'Must-Contain directive missed',
            'expected': ['https://www.santander.co.uk'],
            'delimiter': ' ',
            'value': 'self',
            'anomaly': 'https://www.santander.co.uk'
        }
        self._process_test(headers=headers, status_code=200)
        self.assertIn(expected_report, self.instance.report)

    def test_csp_directive_must_contain_one_value_not_included(self):
        with open(os.path.join(os.path.dirname(__file__), 'testfiles/header_ok.json'), 'r') as f_headers,\
             open(os.path.join(os.path.dirname(__file__), 'testfiles/test_rules.yml'), 'r') as f_rules:
            headers = json.loads(f_headers.read())
            rules = yaml.safe_load(f_rules.read())

        rule_value = rules['Headers']['Content-Security-Policy']
        rule_value['Directives'] = {
            'script-src': {
                'Required': True,
                'Enforce': False,
                'Delimiter': ' ',
                'Value': '',
                'Must-Contain-One': ['https://www.santander.co.uk', 'https://www.google.com']
            }
        }
        self.modify_rules('Content-Security-Policy', rule_value)

        directive = re.search('script-src [^;]*(;)?', headers['Content-Security-Policy']).group()
        headers['Content-Security-Policy'] = headers['Content-Security-Policy'].replace(directive, 'script-src \'self\';')

        expected_report = {
            'severity': 'high',
            'rule': 'Content-Security-Policy - script-src',
            'message': 'Must-Contain-One directive missed',
            'expected': ['https://www.santander.co.uk', 'https://www.google.com'],
            'delimiter': ' ',
            'value': 'self',
            'anomaly': ['https://www.santander.co.uk', 'https://www.google.com']
        }
        self._process_test(headers=headers, status_code=200)
        self.assertIn(expected_report, self.instance.report)

    @staticmethod
    def modify_rules(rule, rule_value):
        with open(os.path.join(os.path.dirname(__file__), 'testfiles/test_rules.yml'), 'r+') as f:
            rules = yaml.safe_load(f.read())
            rules['Headers'][rule] = rule_value
            yaml.dump(rules, f)

    @staticmethod
    def build_error_message(report, expected_report=None):
        if expected_report is None:
            expected_report = []
        elif type(expected_report) is dict:
            expected_report = expected_report.items()

        unexpected_items = []
        for item in report:
            if item not in expected_report:
                unexpected_items.append(item)

        missing_items = []
        for item in expected_report:
            if item not in report:
                missing_items.append(item)

        error_message = ""
        if len(unexpected_items) > 0:
            error_message += "\nThe following items were found but were not expected in the report: \n"
            error_message += json.dumps(unexpected_items, indent=2)

        if len(missing_items) > 0:
            error_message += "\nThe following items were not found but were expected in the report: \n"
            error_message += json.dumps(missing_items, indent=2)

        return error_message

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


# start unittest2 to run these tests
if __name__ == "__main__":
    unittest2.main()
