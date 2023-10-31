import os

import unittest
import yaml

from tests.integration_tests import utils


class TestDrHeader(unittest.TestCase):

    def tearDown(self):
        utils.reset_default_rules()

    def test__should_get_headers_from_url(self):
        report = utils.process_test(url='https://google.com')
        self.assertIsNotNone(report)

    def test_header__should_handle_case_insensitive_header_names(self):
        modify_rule('Content-Security-Policy', {'Required': True})
        headers = utils.add_or_modify_header('Content-Security-Policy', "default-src 'none'")
        headers['CONTENT-SECURITY-POLICY'] = headers.pop('Content-Security-Policy')

        report = utils.process_test(headers=headers)
        self.assertEqual(0, len(report), msg=utils.build_error_message(report))

    def test_header__should_handle_case_insensitive_header_values(self):
        modify_rule('Content-Security-Policy', {'Required': True, 'Must-Contain': ['default-src']})
        headers = utils.add_or_modify_header('Content-Security-Policy', "default-src 'none'")
        headers['Content-Security-Policy'] = headers.pop('Content-Security-Policy').upper()

        report = utils.process_test(headers=headers)
        self.assertEqual(0, len(report), msg=utils.build_error_message(report))

    def test_header__should_not_run_cross_origin_validations_when_cross_origin_isolated_is_false(self):
        headers = utils.delete_headers('Cross-Origin-Embedder-Policy', 'Cross-Origin-Opener-Policy')

        report = utils.process_test(headers=headers, cross_origin_isolated=False)
        self.assertEqual(0, len(report), msg=utils.build_error_message(report))

    def test_header__should_not_validate_an_optional_header_that_is_not_present(self):
        modify_rule('Cache-Control', {'Required': 'Optional', 'Value': ['no-store']})
        headers = utils.delete_headers('Cache-Control')

        report = utils.process_test(headers=headers)
        self.assertEqual(0, len(report), msg=utils.build_error_message(report))

    def test_header__should_validate_an_optional_header_that_is_present(self):
        modify_rule('Cache-Control', {'Required': 'Optional', 'Value': 'no-store'})
        headers = utils.add_or_modify_header('Cache-Control', 'no-cache')

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'Cache-Control',
            'message': 'Value does not match security policy',
            'severity': 'high',
            'value': 'no-cache',
            'expected': ['no-store']
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Cache-Control'))

    def test_header__exists_validation_ko(self):
        modify_rule('Cache-Control', {'Required': True})
        headers = utils.delete_headers('Cache-Control')

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'Cache-Control',
            'message': 'Header not included in response',
            'severity': 'high'
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Cache-Control'))

    def test_header__not_exists_validation_ko(self):
        modify_rule('Cache-Control', {'Required': False})
        headers = utils.add_or_modify_header('Cache-Control', 'private, public')

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'Cache-Control',
            'message': 'Header should not be returned',
            'severity': 'high'
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Cache-Control'))

    def test_header__value_validation_ko(self):
        modify_rule('Cache-Control', {'Required': True, 'Value': ['no-store']})
        headers = utils.add_or_modify_header('Cache-Control', 'no-cache')

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'Cache-Control',
            'message': 'Value does not match security policy',
            'severity': 'high',
            'value': 'no-cache',
            'expected': ['no-store']
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Cache-Control'))

    def test_header__value_any_of_validation_ko(self):
        modify_rule('Cache-Control', {'Required': True, 'Value-Any-Of': ['private', 'no-cache', 'no-transform']})
        headers = utils.add_or_modify_header('Cache-Control', 'private, public, no-transform')

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'Cache-Control',
            'message': 'Value does not match security policy. At least one of the expected items was expected',
            'severity': 'high',
            'value': 'private, public, no-transform',
            'expected': ['private', 'no-cache', 'no-transform'],
            'delimiter': ',',
            'anomalies': ['public']
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Cache-Control'))

    def test_header__value_one_of_validation_ko(self):
        modify_rule('Cache-Control', {'Required': True, 'Value-One-Of': ['no-cache', 'no-store']})
        headers = utils.add_or_modify_header('Cache-Control', 'private, must-revalidate')

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'Cache-Control',
            'message': 'Value does not match security policy. Exactly one of the expected items was expected',
            'severity': 'high',
            'value': 'private, must-revalidate',
            'expected': ['no-cache', 'no-store']
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Cache-Control'))

    def test_header__must_avoid_validation_ko(self):
        modify_rule('Cache-Control', {'Required': True, 'Must-Avoid': ['private', 'public']})
        headers = utils.add_or_modify_header('Cache-Control', 'private, must-understand')

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'Cache-Control',
            'message': 'Must-Avoid directive included',
            'severity': 'high',
            'value': 'private, must-understand',
            'avoid': ['private', 'public'],
            'anomalies': ['private']
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Cache-Control'))

    def test_header__must_contain_validation_ko(self):
        modify_rule('Cache-Control', {'Required': True, 'Must-Contain': ['must-revalidate']})
        headers = utils.add_or_modify_header('Cache-Control', 'private')

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'Cache-Control',
            'message': 'Must-Contain directive missed',
            'severity': 'high',
            'value': 'private',
            'expected': ['must-revalidate'],
            'anomalies': ['must-revalidate']
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Cache-Control'))

    def test_header__must_contain_one_validation_ko(self):
        modify_rule('Cache-Control', {'Required': True, 'Must-Contain-One': ['must-revalidate', 'no-cache']})
        headers = utils.add_or_modify_header('Cache-Control', 'private')

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'Cache-Control',
            'message': 'Must-Contain-One directive missed. At least one of the expected items was expected',
            'severity': 'high',
            'value': 'private',
            'expected': ['must-revalidate', 'no-cache']
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Cache-Control'))

    def test_directive__value_validation_ko(self):
        modify_rule('Content-Security-Policy', {'Required': True, 'Directives': {'style-src': {'Required': True, 'Value': ['self']}}})
        headers = utils.add_or_modify_header('Content-Security-Policy', 'style-src https://example.com')

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'Content-Security-Policy - style-src',
            'message': 'Value does not match security policy',
            'severity': 'high',
            'value': 'https://example.com',
            'expected': ['self']
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Content-Security-Policy'))

    def test_directive__value_any_of_validation_ko(self):
        modify_rule('Content-Security-Policy', {'Required': True, 'Directives': {'style-src': {'Required': True, 'Value-Any-Of': ['https://example1.com', 'https://example2.com']}}})
        headers = utils.add_or_modify_header('Content-Security-Policy', 'style-src https://example.com')

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'Content-Security-Policy - style-src',
            'message': 'Value does not match security policy. At least one of the expected items was expected',
            'severity': 'high',
            'value': 'https://example.com',
            'expected': ['https://example1.com', 'https://example2.com'],
            'delimiter': ' ',
            'anomalies': ['https://example.com']
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Content-Security-Policy'))

    def test_directive__value_one_of_validation_ko(self):
        modify_rule('Content-Security-Policy', {'Required': True, 'Directives': {'style-src': {'Required': True, 'Value-One-Of': ['none', 'self']}}})
        headers = utils.add_or_modify_header('Content-Security-Policy', 'style-src https://example.com')

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'Content-Security-Policy - style-src',
            'message': 'Value does not match security policy. Exactly one of the expected items was expected',
            'severity': 'high',
            'value': 'https://example.com',
            'expected': ['none', 'self']
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Content-Security-Policy'))

    def test_directive__must_avoid_validation_ko(self):
        modify_rule('Content-Security-Policy', {'Required': True, 'Directives': {'style-src': {'Required': True, 'Must-Avoid': ['unsafe-inline']}}})
        headers = utils.add_or_modify_header('Content-Security-Policy', "style-src 'unsafe-inline'")

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'Content-Security-Policy - style-src',
            'message': 'Must-Avoid directive included',
            'severity': 'high',
            'value': "'unsafe-inline'",
            'avoid': ['unsafe-inline'],
            'anomalies': ['unsafe-inline']
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Content-Security-Policy'))

    def test_directive__must_contain_validation_ko(self):
        modify_rule('Content-Security-Policy', {'Required': True, 'Directives': {'style-src': {'Required': True, 'Must-Contain': ['https://example.com']}}})
        headers = utils.add_or_modify_header('Content-Security-Policy', "style-src 'self'")

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'Content-Security-Policy - style-src',
            'message': 'Must-Contain directive missed',
            'severity': 'high',
            'value': "'self'",
            'expected': ['https://example.com'],
            'anomalies': ['https://example.com']
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Content-Security-Policy'))

    def test_directive__must_contain_one_validation_ko(self):
        modify_rule('Content-Security-Policy', {'Required': True, 'Directives': {'style-src': {'Required': True, 'Must-Contain-One': ['https://example1.com', 'https://example2.com']}}})
        headers = utils.add_or_modify_header('Content-Security-Policy', "style-src 'self'")

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'Content-Security-Policy - style-src',
            'message': 'Must-Contain-One directive missed. At least one of the expected items was expected',
            'severity': 'high',
            'value': "'self'",
            'expected': ['https://example1.com', 'https://example2.com']
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Content-Security-Policy'))

    def test_cookie__exists_validation_ko(self):
        modify_rule('Set-Cookie', {'Required': True, 'Cookies': {'session': {'Required': True}}})
        headers = utils.add_or_modify_header('Set-Cookie', ['tracker=657488329; HttpOnly; Secure'])

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'Set-Cookie - session',
            'message': 'Cookie not included in response',
            'severity': 'high'
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Set-Cookie'))

    def test_cookie__not_exists_validation_ko(self):
        modify_rule('Set-Cookie', {'Required': True, 'Cookies': {'session': {'Required': False}}})
        headers = utils.add_or_modify_header('Set-Cookie', ['session=657488329; HttpOnly; Secure'])

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'Set-Cookie - session',
            'message': 'Cookie should not be returned',
            'severity': 'high'
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Set-Cookie'))

    def test_cookie__must_avoid_validation_ko(self):
        modify_rule('Set-Cookie', {'Required': True, 'Cookies': {'session': {'Required': True, 'Must-Avoid': ['Path']}}})
        headers = utils.add_or_modify_header('Set-Cookie', ['session=657488329; HttpOnly; Secure; Path=/docs'])

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'Set-Cookie - session',
            'message': 'Must-Avoid directive included',
            'severity': 'high',
            'value': '657488329; HttpOnly; Secure; Path=/docs',
            'avoid': ['Path'],
            'anomalies': ['Path']
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Set-Cookie'))

    def test_cookie__must_contain_validation_ko(self):
        modify_rule('Set-Cookie', {'Required': True, 'Cookies': {'session': {'Required': True, 'Must-Contain': ['HttpOnly', 'SameSite=Strict', 'Secure']}}})
        headers = utils.add_or_modify_header('Set-Cookie', ['session=657488329; HttpOnly; SameSite=Lax; Secure'])

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'Set-Cookie - session',
            'message': 'Must-Contain directive missed',
            'severity': 'high',
            'value': '657488329; HttpOnly; SameSite=Lax; Secure',
            'expected': ['HttpOnly', 'SameSite=Strict', 'Secure'],
            'delimiter': ';',
            'anomalies': ['SameSite=Strict']
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Set-Cookie'))

    def test_cookie__must_contain_one_validation_ko(self):
        modify_rule('Set-Cookie', {'Required': True, 'Cookies': {'session': {'Required': True, 'Must-Contain-One': ['Expires', 'Max-Age']}}})
        headers = utils.add_or_modify_header('Set-Cookie', ['session=657488329; HttpOnly; Secure'])

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'Set-Cookie - session',
            'message': 'Must-Contain-One directive missed. At least one of the expected items was expected',
            'severity': 'high',
            'value': '657488329; HttpOnly; Secure',
            'expected': ['Expires', 'Max-Age']
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Set-Cookie'))


def modify_rule(rule_name, rule_value):
    with open(os.path.join(os.path.dirname(__file__), '../test_resources/default_rules.yml'), 'w') as rules:
        modified_rule = {rule_name: rule_value}
        yaml.dump(modified_rule, rules, sort_keys=False)
