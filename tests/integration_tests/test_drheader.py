import os

import yaml

from tests.integration_tests.test_base import TestBase


class TestDrHeader(TestBase):

    def test_get_headers_from_url_ok(self):
        report = super().process_test(url='https://google.com')
        self.assertIsNotNone(report)

    def test_headers_case_insensitive_keys_ok(self):
        self.modify_rule('Content-Security-Policy', {'Required': True})
        headers = super().add_or_modify_header('Content-Security-Policy', "default-src 'none'")
        headers['CONTENT-SECURITY-POLICY'] = headers.pop('Content-Security-Policy')

        report = super().process_test(headers=headers)
        self.assertEqual(0, len(report), msg=super().build_error_message(report))

    def test_headers_case_insensitive_values_ok(self):
        self.modify_rule('Content-Security-Policy', {'Required': True, 'Must-Contain': ['default-src']})
        headers = super().add_or_modify_header('Content-Security-Policy', "default-src 'none'")
        headers['Content-Security-Policy'] = headers.pop('Content-Security-Policy').upper()

        report = super().process_test(headers=headers)
        self.assertEqual(0, len(report), msg=super().build_error_message(report))

    def test_headers_cross_origin_isolated_disabled_ok(self):
        headers = super().delete_headers('Cross-Origin-Embedder-Policy', 'Cross-Origin-Opener-Policy')

        report = super().process_test(headers=headers, cross_origin_isolated=False)
        self.assertEqual(0, len(report), msg=super().build_error_message(report))

    def test_optional_header_not_present_ok(self):
        self.modify_rule('X-XSS-Protection', {'Required': 'Optional', 'Value': ['0']})
        headers = super().delete_headers('X-XSS-Protection')

        report = super().process_test(headers=headers)
        self.assertEqual(0, len(report), msg=super().build_error_message(report))

    def test_optional_header_ko(self):
        self.modify_rule('X-XSS-Protection', {'Required': 'Optional', 'Value': 0})
        headers = super().add_or_modify_header('X-XSS-Protection', '1; mode=block')

        report = super().process_test(headers=headers)
        expected = {
            'rule': 'X-XSS-Protection',
            'severity': 'high',
            'message': 'Value does not match security policy. All of the expected items were expected',
            'expected': ['0'],
            'value': '1; mode=block'
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'X-XSS-Protection'))

    def test_header_required_ko(self):
        self.modify_rule('Strict-Transport-Security', {'Required': True})
        headers = super().delete_headers('Strict-Transport-Security')

        report = super().process_test(headers=headers)
        expected = {
            'rule': 'Strict-Transport-Security',
            'severity': 'high',
            'message': 'Header not included in response'
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'Strict-Transport-Security'))

    def test_header_disallowed_ko(self):
        self.modify_rule('Server', {'Required': False})
        headers = super().add_or_modify_header('Server', 'Apache/2.4.1 (Unix)')

        report = super().process_test(headers=headers)
        expected = {
            'severity': 'high',
            'rule': 'Server',
            'message': 'Header should not be returned'
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'Server'))

    def test_header_enforced_value_ko(self):
        self.modify_rule('X-Frame-Options', {'Required': True, 'Value': ['DENY']})
        headers = super().add_or_modify_header('X-Frame-Options', 'SAMEORIGIN')

        report = super().process_test(headers=headers)
        expected = {
            'rule': 'X-Frame-Options',
            'severity': 'high',
            'message': 'Value does not match security policy. All of the expected items were expected',
            'expected': ['DENY'],
            'value': 'SAMEORIGIN'
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'X-Frame-Options'))

    def test_header_enforced_value_any_of_ko(self):
        self.modify_rule('Referrer-Policy', {'Required': True, 'Value-Any-Of': ['same-origin', 'no-referrer']})
        headers = super().add_or_modify_header('Referrer-Policy', 'same-origin, origin-when-cross-origin')

        report = super().process_test(headers=headers)
        expected = {
            'rule': 'Referrer-Policy',
            'severity': 'high',
            'message': 'Value does not match security policy. At least one of the expected items was expected',
            'value': 'same-origin, origin-when-cross-origin',
            'expected': ['same-origin', 'no-referrer'],
            'delimiter': ',',
            'anomalies': ['origin-when-cross-origin']
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'Referrer-Policy'))

    def test_header_enforced_value_one_of_ko(self):
        self.modify_rule('Referrer-Policy', {'Required': True, 'Value-One-Of': ['same-origin', 'no-referrer']})
        headers = super().add_or_modify_header('Referrer-Policy', 'origin-when-cross-origin')

        report = super().process_test(headers=headers)
        expected = {
            'rule': 'Referrer-Policy',
            'severity': 'high',
            'message': 'Value does not match security policy. Exactly one of the expected items was expected',
            'value': 'origin-when-cross-origin',
            'expected': ['same-origin', 'no-referrer']
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'Referrer-Policy'))

    def test_header_must_avoid_ko(self):
        self.modify_rule('Content-Security-Policy', {'Required': True, 'Must-Avoid': ['unsafe-inline', 'unsafe-eval']})
        headers = super().add_or_modify_header('Content-Security-Policy', "default-src 'self'; style-src 'unsafe-eval'")

        report = super().process_test(headers=headers)
        expected = {
            'rule': 'Content-Security-Policy - style-src',
            'severity': 'medium',
            'message': 'Must-Avoid directive included',
            'avoid': ['unsafe-inline', 'unsafe-eval'],
            'value': "'unsafe-eval'",
            'anomalies': ['unsafe-eval']
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'Content-Security-Policy'))

    def test_header_must_contain_ko(self):
        self.modify_rule('Set-Cookie', {'Required': True, 'Must-Contain': ['Secure', 'HttpOnly']})
        headers = super().add_or_modify_header('Set-Cookie', ['session_id=647388212; HttpOnly; SameSite=Strict'])

        report = super().process_test(headers=headers)
        expected = {
            'rule': 'Set-Cookie',
            'severity': 'medium',
            'message': 'Must-Contain directive missed. All of the expected items were expected',
            'expected': ['Secure', 'HttpOnly'],
            'value': 'session_id=647388212; HttpOnly; SameSite=Strict',
            'anomalies': ['Secure'],
            'delimiter': ';'
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'Set-Cookie'))

    def test_header_must_contain_one_ko(self):
        self.modify_rule('Cache-Control', {'Required': True, 'Must-Contain-One': ['must-revalidate', 'no-cache']})
        headers = super().add_or_modify_header('Cache-Control', 'public')

        report = super().process_test(headers=headers)
        expected = {
            'rule': 'Cache-Control',
            'severity': 'high',
            'message': 'Must-Contain-One directive missed. At least one of the expected items was expected',
            'expected': ['must-revalidate', 'no-cache'],
            'value': 'public'
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'Cache-Control'))

    def test_directive_enforced_value_ko(self):
        self.modify_rule('Content-Security-Policy', {'Required': True, 'Directives': {'script-src': {'Required': True, 'Value': ['self']}}})
        headers = super().add_or_modify_header('Content-Security-Policy', 'script-src https://example.com')

        report = super().process_test(headers=headers)
        expected = {
            'rule': 'Content-Security-Policy - script-src',
            'severity': 'high',
            'message': 'Value does not match security policy. All of the expected items were expected',
            'expected': ['self'],
            'value': 'https://example.com'
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'Content-Security-Policy'))

    def test_directive_enforced_value_any_of_ko(self):
        self.modify_rule('Content-Security-Policy', {'Required': True, 'Directives': {'style-src': {'Required': True, 'Value-Any-Of': ['https://example1.com', 'https://example2.com']}}})
        headers = super().add_or_modify_header('Content-Security-Policy', 'style-src https://example.com')

        report = super().process_test(headers=headers)
        expected = {
            'rule': 'Content-Security-Policy - style-src',
            'severity': 'high',
            'message': 'Value does not match security policy. At least one of the expected items was expected',
            'value': 'https://example.com',
            'expected': ['https://example1.com', 'https://example2.com'],
            'anomalies': ['https://example.com'],
            'delimiter': ' '
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'Content-Security-Policy'))

    def test_directive_enforced_value_one_of_ko(self):
        self.modify_rule('Content-Security-Policy', {'Required': True, 'Directives': {'default-src': {'Required': True, 'Value-One-Of': ['none', 'self']}}})
        headers = super().add_or_modify_header('Content-Security-Policy', 'default-src https://example.com')

        report = super().process_test(headers=headers)
        expected = {
            'rule': 'Content-Security-Policy - default-src',
            'severity': 'high',
            'message': 'Value does not match security policy. Exactly one of the expected items was expected',
            'value': 'https://example.com',
            'expected': ['none', 'self']
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'Content-Security-Policy'))

    def test_directive_must_avoid_ko(self):
        self.modify_rule('Content-Security-Policy', {'Required': True, 'Directives': {'sandbox': {'Required': True, 'Must-Avoid': ['allow-scripts']}}})
        headers = super().add_or_modify_header('Content-Security-Policy', 'sandbox allow-scripts allow-modals')

        report = super().process_test(headers=headers)
        expected = {
            'rule': 'Content-Security-Policy - sandbox',
            'severity': 'medium',
            'message': 'Must-Avoid directive included',
            'avoid': ['allow-scripts'],
            'value': 'allow-scripts allow-modals',
            'anomalies': ['allow-scripts']
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'Content-Security-Policy'))

    def test_directive_must_contain_ko(self):
        self.modify_rule('Content-Security-Policy', {'Required': True, 'Directives': {'connect-src': {'Required': True, 'Must-Contain': ['https://example.com']}}})
        headers = super().add_or_modify_header('Content-Security-Policy', "default-src 'none'; connect-src 'self'")

        report = super().process_test(headers=headers)
        expected = {
            'rule': 'Content-Security-Policy - connect-src',
            'severity': 'medium',
            'message': 'Must-Contain directive missed. All of the expected items were expected',
            'expected': ['https://example.com'],
            'value': "'self'",
            'anomalies': ['https://example.com']
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'Content-Security-Policy'))

    def test_directive_must_contain_one_ko(self):
        self.modify_rule('Content-Security-Policy', {'Required': True, 'Directives': {'base-uri': {'Required': True, 'Must-Contain-One': ['https://example1.com', 'https://example2.com']}}})
        headers = super().add_or_modify_header('Content-Security-Policy', "default-src 'none'; base-uri 'self'")

        report = super().process_test(headers=headers)
        expected = {
            'rule': 'Content-Security-Policy - base-uri',
            'severity': 'high',
            'message': 'Must-Contain-One directive missed. At least one of the expected items was expected',
            'expected': ['https://example1.com', 'https://example2.com'],
            'value': "'self'"
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'Content-Security-Policy'))

    @staticmethod
    def modify_rule(rule_name, rule_value):
        with open(os.path.join(os.path.dirname(__file__), '../test_resources/default_rules.yml'), 'w') as rules:
            modified_rule = {'Headers': {rule_name: rule_value}}
            yaml.dump(modified_rule, rules, sort_keys=False)
