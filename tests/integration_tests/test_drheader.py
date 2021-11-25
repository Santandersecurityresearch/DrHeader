import os

import yaml

from tests.integration_tests.test_base import TestBase


class TestDrHeader(TestBase):

    def test_get_headers_from_url_ok(self):
        self.process_test(url='https://google.com')
        self.assertNotEqual(self.instance.report, None)

    def test_headers_case_insensitive_keys_ok(self):
        rule_value = {'Required': True, 'Enforce': False}
        self.modify_rule('Content-Security-Policy', rule_value)

        headers = self.modify_header('Content-Security-Policy', "default-src 'none'")
        headers['CONTENT-SECURITY-POLICY'] = headers.pop('Content-Security-Policy')
        unexpected_item_regex = ".*" \
            "'rule': 'Content-Security-Policy', " \
            "(.*, )?" \
            "'message': 'Header not included in response'" \
            ".*"

        self.process_test(headers=headers, status_code=200)
        self.assertNotRegex(str(self.instance.report), unexpected_item_regex,
                            msg=self.build_error_message(self.instance.report, rule='Content-Security-Policy', append_text='Regex matched'))

    def test_headers_case_insensitive_values_ok(self):
        rule_value = {'Required': True, 'Enforce': False, 'Must-Contain': ["default-src 'none'"]}
        self.modify_rule('Content-Security-Policy', rule_value)

        headers = self.modify_header('Content-Security-Policy', "default-src 'none'")
        headers['Content-Security-Policy'] = headers.pop('Content-Security-Policy').upper()
        unexpected_item_regex = ".*" \
            "'rule': 'Content-Security-Policy', " \
            "(.*, )?" \
            "'message': 'Must-Contain directive missed'" \
            ".*"

        self.process_test(headers=headers, status_code=200)
        self.assertNotRegex(str(self.instance.report), unexpected_item_regex,
                            msg=self.build_error_message(self.instance.report, rule='Content-Security-Policy', append_text='Regex matched'))

    def test_optional_header_not_present_ok(self):
        rule_value = {'Required': 'Optional', 'Enforce': True, 'Value': ['0']}
        self.modify_rule('X-XSS-Protection', rule_value)

        headers = self.modify_header('X-XSS-Protection', None)
        unexpected_item_regex = ".*" \
            "'rule': 'X-XSS-Protection', " \
            "(.*, )?" \
            "'message': 'Header not included in response'" \
            ".*"

        self.process_test(headers=headers, status_code=200)
        self.assertNotRegex(str(self.instance.report), unexpected_item_regex,
                            msg=self.build_error_message(self.instance.report, rule='X-XSS-Protection', append_text='Regex matched'))

    def test_optional_header_ko(self):
        rule_value = {'Required': 'Optional', 'Enforce': True, 'Value': ['0']}
        self.modify_rule('X-XSS-Protection', rule_value)

        headers = self.modify_header('X-XSS-Protection', '1; mode=block')
        expected_report_item = {
            'rule': 'X-XSS-Protection',
            'severity': 'high',
            'message': 'Value does not match security policy',
            'expected': ['0'],
            'delimiter': ';',
            'value': '1; mode=block'
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='X-XSS-Protection'))

    def test_header_required_ko(self):
        rule_value = {'Required': True, 'Enforce': False}
        self.modify_rule('Strict-Transport-Security', rule_value)

        headers = self.modify_header('Strict-Transport-Security', None)
        expected_report_item = {
            'rule': 'Strict-Transport-Security',
            'severity': 'high',
            'message': 'Header not included in response'
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='Strict-Transport-Security'))

    def test_header_disallowed_ko(self):
        rule_value = {'Required': False}
        self.modify_rule('Server', rule_value)

        headers = self.modify_header('Server', 'Apache/2.4.1 (Unix)')
        expected_report_item = {
            'severity': 'high',
            'rule': 'Server',
            'message': 'Header should not be returned'
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='Server'))

    def test_header_enforced_value_ko(self):
        rule_value = {'Required': True, 'Enforce': True, 'Value': ['DENY']}
        self.modify_rule('X-Frame-Options', rule_value)

        headers = self.modify_header('X-Frame-Options', 'SAMEORIGIN')
        expected_report_item = {
            'rule': 'X-Frame-Options',
            'severity': 'high',
            'message': 'Value does not match security policy',
            'expected': ['deny'],
            'delimiter': ';',
            'value': 'sameorigin'
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='X-Frame-Options'))

    def test_header_must_contain_ko(self):
        rule_value = {'Required': True, 'Enforce': False, 'Must-Contain': ['Secure', 'HttpOnly']}
        self.modify_rule('Set-Cookie', rule_value)

        headers = self.modify_header('Set-Cookie', ['session_id=647388212; HttpOnly; SameSite=Strict'])
        expected_report_item = {
            'rule': 'Set-Cookie',
            'severity': 'high',
            'message': 'Must-Contain directive missed',
            'expected': ['secure', 'httponly'],
            'delimiter': ';',
            'value': 'session_id=647388212; httponly; samesite=strict',
            'anomaly': 'secure'
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='Set-Cookie'))

    def test_header_must_contain_one_ko(self):
        rule_value = {'Required': True, 'Enforce': False, 'Must-Contain-One': ['must-revalidate', 'no-cache']}
        self.modify_rule('Cache-Control', rule_value)

        headers = self.modify_header('Cache-Control', 'public')
        expected_report_item = {
            'rule': 'Cache-Control',
            'severity': 'high',
            'message': 'Must-Contain-One directive missed',
            'expected': ['must-revalidate', 'no-cache'],
            'delimiter': ';',
            'value': 'public',
            'anomaly': ['must-revalidate', 'no-cache']
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='Cache-Control'))

    def test_header_must_avoid_ko(self):
        rule_value = {'Required': True, 'Enforce': False, 'Must-Avoid': ['unsafe-inline', 'unsafe-eval']}
        self.modify_rule('Content-Security-Policy', rule_value)

        headers = self.modify_header('Content-Security-Policy', "default-src 'self'; connect-src 'unsafe-inline'")
        expected_report_item = {
            'rule': 'Content-Security-Policy - connect-src',
            'severity': 'medium',
            'message': 'Must-Avoid directive included',
            'avoid': ['unsafe-inline', 'unsafe-eval'],
            'delimiter': ';',
            'value': 'unsafe-inline',
            'anomaly': 'unsafe-inline'
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='Content-Security-Policy'))

    def test_directive_required_ko(self):
        rule_value = {'Required': True, 'Enforce': False, 'Directives': {'default-src': {'Required': True, 'Enforce': False}}}
        self.modify_rule('Content-Security-Policy', rule_value)

        headers = self.modify_header('Content-Security-Policy', '', pattern='default-src [^;]*(;)?')
        expected_report_item = {
            'rule': 'Content-Security-Policy - default-src',
            'severity': 'high',
            'message': 'Directive not included in response'
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='Content-Security-Policy - default-src'))

    def test_directive_disallowed_ko(self):
        rule_value = {'Required': True, 'Enforce': False, 'Directives': {'referrer': {'Required': False}}}
        self.modify_rule('Content-Security-Policy', rule_value)

        headers = self.modify_header('Content-Security-Policy', 'referrer no-referrer;', pattern='referrer [^;]*(;)?')
        expected_report_item = {
            'rule': 'Content-Security-Policy - referrer',
            'severity': 'high',
            'message': 'Directive should not be returned'
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='Content-Security-Policy - referrer'))

    def test_directive_enforced_value_ko(self):
        rule_value = {'Required': True, 'Enforce': False, 'Directives': {'script-src': {'Required': True, 'Enforce': True, 'Delimiter': ' ', 'Value': ['self']}}}
        self.modify_rule('Content-Security-Policy', rule_value)

        headers = self.modify_header('Content-Security-Policy', 'script-src https://www.santander.co.uk;', pattern='script-src [^;]*(;)?')
        expected_report_item = {
            'rule': 'Content-Security-Policy - script-src',
            'severity': 'high',
            'message': 'Value does not match security policy',
            'expected': ['self'],
            'delimiter': ' ',
            'value': 'https://www.santander.co.uk'
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='Content-Security-Policy - script-src'))

    def test_directive_must_contain_ko(self):
        rule_value = {'Required': True, 'Enforce': False, 'Directives': {'connect-src': {'Required': True, 'Enforce': False, 'Delimiter': ' ', 'Must-Contain': ['https://www.santander.co.uk']}}}
        self.modify_rule('Content-Security-Policy', rule_value)

        headers = self.modify_header('Content-Security-Policy', "connect-src 'self';", pattern='connect-src [^;]*(;)?')
        expected_report_item = {
            'rule': 'Content-Security-Policy - connect-src',
            'severity': 'medium',
            'message': 'Must-Contain directive missed',
            'expected': ['https://www.santander.co.uk'],
            'delimiter': ' ',
            'value': 'self',
            'anomaly': 'https://www.santander.co.uk'
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='Content-Security-Policy - connect-src'))

    def test_directive_must_contain_one_ko(self):
        rule_value = {'Required': True, 'Enforce': False, 'Directives': {'base-uri': {'Required': True, 'Enforce': False, 'Delimiter': ' ', 'Must-Contain-One': ['https://www.santander.co.uk', 'https://www.santander.com']}}}
        self.modify_rule('Content-Security-Policy', rule_value)

        headers = self.modify_header('Content-Security-Policy', "base-uri 'self';", pattern='base-uri [^;]*(;)?')
        expected_report_item = {
            'rule': 'Content-Security-Policy - base-uri',
            'severity': 'high',
            'message': 'Must-Contain-One directive missed',
            'expected': ['https://www.santander.co.uk', 'https://www.santander.com'],
            'delimiter': ' ',
            'value': 'self',
            'anomaly': ['https://www.santander.co.uk', 'https://www.santander.com']
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='Content-Security-Policy - base-uri'))

    def test_directive_must_avoid_ko(self):
        rule_value = {'Required': True, 'Enforce': False, 'Directives': {'sandbox': {'Required': True, 'Enforce': False, 'Delimiter': ' ', 'Must-Avoid': ['allow-downloads']}}}
        self.modify_rule('Content-Security-Policy', rule_value)

        headers = self.modify_header('Content-Security-Policy', 'sandbox allow-downloads allow-modals;', pattern='sandbox [^;]*(;)?')
        expected_report_item = {
            'rule': 'Content-Security-Policy - sandbox',
            'severity': 'medium',
            'message': 'Must-Avoid directive included',
            'avoid': ['allow-downloads'],
            'delimiter': ' ',
            'value': 'allow-downloads allow-modals',
            'anomaly': 'allow-downloads'
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='Content-Security-Policy - sandbox'))

    @staticmethod
    def modify_rule(rule_name, update_value, modify_key=None):
        with open(os.path.join(os.path.dirname(__file__), '../test_resources/default_rules.yml'), 'r+') as test_rules_file:
            rules = yaml.safe_load(test_rules_file.read())

            if modify_key:
                rules['Headers'][rule_name][modify_key] = update_value
            elif update_value is None:
                rules['Headers'].pop(rule_name)
            else:
                rules['Headers'][rule_name] = update_value
            yaml.dump(rules, test_rules_file)
