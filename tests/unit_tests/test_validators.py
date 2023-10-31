from unittest import mock

import unittest
from requests import structures

from drheader import report, utils
from drheader.validators.cookie_validator import CookieValidator
from drheader.validators.header_validator import HeaderValidator


class TestBase(unittest.TestCase):

    def assert_report_items_equal(self, expected_report_item, observed_report_item, msg=None):
        does_validate = True

        for field in expected_report_item._asdict():
            expected = getattr(expected_report_item, field)
            observed = getattr(observed_report_item, field)
            if not expected == observed:
                msg += f"\tNon-matching values for field '{field}'. Expected: '{expected}'; Observed: '{observed}'\n"
                does_validate = False
        if not does_validate:
            raise self.failureException(msg)


class TestCookieValidator(TestBase):

    def setUp(self):
        self.validator = CookieValidator(cookies=structures.CaseInsensitiveDict())
        self.addTypeEqualityFunc(report.ReportItem, super().assert_report_items_equal)

    @mock.patch('drheader.utils.parse_policy')
    def test_validate_must_avoid__should_validate_named_cookie(self, parse_policy_mock):
        config = structures.CaseInsensitiveDict({
            'required': True,
            'must-avoid': ['samesite=lax'],
            'delimiters': {'item_delimiter': ';', 'key_value_delimiter': '='}
        })
        self.validator.cookies['session'] = '657488329; samesite=lax'
        parse_policy_mock.return_value = ['657488329', 'samesite=lax', 'samesite']

        response = self.validator.must_avoid(config, 'set-cookie', cookie='session')
        expected = report.ReportItem('high', report.ErrorType.AVOID, 'set-cookie', cookie='session', value='657488329; samesite=lax', avoid=['samesite=lax'], anomalies=['samesite=lax'])
        self.assertEqual(expected, response, msg='The report items are not equal:\n')

    @mock.patch('drheader.utils.parse_policy')
    def test_validate_must_contain__should_validate_named_cookie(self, parse_policy_mock):
        config = structures.CaseInsensitiveDict({
            'required': True,
            'must-contain': ['httponly', 'secure'],
            'delimiters': {'item_delimiter': ';', 'key_value_delimiter': '='}
        })
        self.validator.cookies['session'] = '657488329; httponly; samesite=strict'
        parse_policy_mock.return_value = ['657488329', 'httponly', 'samesite=strict', 'samesite']

        response = self.validator.must_contain(config, 'set-cookie', cookie='session')
        expected = report.ReportItem('high', report.ErrorType.CONTAIN, 'set-cookie', cookie='session', value='657488329; httponly; samesite=strict', expected=['httponly', 'secure'], delimiter=';', anomalies=['secure'])
        self.assertEqual(expected, response, msg='The report items are not equal:\n')

    @mock.patch('drheader.utils.parse_policy')
    def test_validate_must_contain_one__should_validate_named_cookie(self, parse_policy_mock):
        config = structures.CaseInsensitiveDict({
            'required': True,
            'must-contain-one': ['expires', 'max-age'],
            'delimiters': {'item_delimiter': ';', 'key_value_delimiter': '='}
        })
        self.validator.cookies['session'] = '657488329; httponly; samesite=strict'
        parse_policy_mock.return_value = ['657488329', 'samesite=strict', 'samesite']

        response = self.validator.must_contain_one(config, 'set-cookie', cookie='session')
        expected = report.ReportItem('high', report.ErrorType.CONTAIN_ONE, 'set-cookie', cookie='session', value='657488329; httponly; samesite=strict', expected=['expires', 'max-age'])
        self.assertEqual(expected, response, msg='The report items are not equal:\n')


class TestHeaderValidator(TestBase):

    def setUp(self):
        self.validator = HeaderValidator(headers=structures.CaseInsensitiveDict())
        self.addTypeEqualityFunc(report.ReportItem, super().assert_report_items_equal)

    @mock.patch('drheader.utils.parse_policy')
    def test_validate_value__should_enforce_order_when_preserve_order_is_true(self, parse_policy_mock):
        config = structures.CaseInsensitiveDict({
            'required': True,
            'value': ['no-referrer', 'strict-origin-when-cross-origin'],
            'delimiters': {'item_delimiter': ','},
            'preserve-order': True
        })
        self.validator.headers['referrer-policy'] = 'strict-origin-when-cross-origin, no-referrer'
        parse_policy_mock.return_value = ['strict-origin-when-cross-origin', 'no-referrer']

        response = self.validator.value(config, 'referrer-policy')
        expected = report.ReportItem('high', report.ErrorType.VALUE, 'referrer-policy', value='strict-origin-when-cross-origin, no-referrer', expected=['no-referrer', 'strict-origin-when-cross-origin'], delimiter=',')
        self.assertEqual(expected, response, msg='The report items are not equal:\n')

    @mock.patch('drheader.utils.parse_policy')
    def test_validate_must_avoid_for_policy_header__should_validate_standalone_directive(self, parse_policy_mock):
        config = structures.CaseInsensitiveDict({
            'required': True,
            'must-avoid': ['block-all-mixed-content'],
            'delimiters': {'item_delimiter': ';', 'key_value_delimiter': ' ', 'value_delimiter': ' ', 'strip': '\' '}
        })
        self.validator.headers['content-security-policy'] = "default-src 'none'; block-all-mixed-content"

        parse_policy_mock.return_value = [
            "default-src 'none'",
            utils.KeyValueDirective(key='default-src', value=['none'], raw_value="'none'"),
            'block-all-mixed-content'
        ]

        response = self.validator.must_avoid(config, 'content-security-policy')
        expected = report.ReportItem('high', report.ErrorType.AVOID, 'content-security-policy', value="default-src 'none'; block-all-mixed-content", avoid=['block-all-mixed-content'], anomalies=['block-all-mixed-content'])
        self.assertEqual(expected, response[0], msg='The report items are not equal:\n')

    @mock.patch('drheader.utils.parse_policy')
    def test_validate_must_avoid_for_policy_header__should_validate_key_value_directive(self, parse_policy_mock):
        config = structures.CaseInsensitiveDict({
            'required': True,
            'must-avoid': ['script-src'],
            'delimiters': {'item_delimiter': ';', 'key_value_delimiter': ' ', 'value_delimiter': ' ', 'strip': '\' '}
        })
        self.validator.headers['content-security-policy'] = "default-src 'none'; script-src https://example.com"

        parse_policy_mock.return_value = [
            "default-src 'none'",
            utils.KeyValueDirective(key='default-src', value=['none'], raw_value="'none'"),
            'script-src https://example.com',
            utils.KeyValueDirective(key='script-src', value=['https://example.com'], raw_value='https://example.com')
        ]

        response = self.validator.must_avoid(config, 'content-security-policy')
        expected = report.ReportItem('high', report.ErrorType.AVOID, 'content-security-policy', value="default-src 'none'; script-src https://example.com", avoid=['script-src'], anomalies=['script-src'])
        self.assertEqual(expected, response[0], msg='The report items are not equal:\n')

    @mock.patch('drheader.utils.parse_policy')
    def test_validate_must_avoid_for_policy_header__should_validate_keyword_value(self, parse_policy_mock):
        config = structures.CaseInsensitiveDict({
            'required': True,
            'must-avoid': ['unsafe-inline'],
            'delimiters': {'item_delimiter': ';', 'key_value_delimiter': ' ', 'value_delimiter': ' ', 'strip': '\' '}
        })
        self.validator.headers['content-security-policy'] = "default-src 'none'; script-src 'unsafe-inline'"

        parse_policy_mock.return_value = [
            "default-src 'none'",
            utils.KeyValueDirective(key='default-src', value=['none'], raw_value="'none'"),
            "script-src 'unsafe-inline'",
            utils.KeyValueDirective(key='script-src', value=['unsafe-inline'], raw_value="'unsafe-inline'")
        ]

        response = self.validator.must_avoid(config, 'content-security-policy')
        expected = report.ReportItem('high', report.ErrorType.AVOID, 'content-security-policy', directive='script-src', value="'unsafe-inline'", avoid=['unsafe-inline'], anomalies=['unsafe-inline'])
        self.assertEqual(expected, response[0], msg='The report items are not equal:\n')

    @mock.patch('drheader.utils.parse_policy')
    def test_validate_must_avoid_for_policy_header__should_report_all_non_compliant_directives(self, parse_policy_mock):
        config = structures.CaseInsensitiveDict({
            'required': True,
            'must-avoid': ['unsafe-inline'],
            'delimiters': {'item_delimiter': ';', 'key_value_delimiter': ' ', 'value_delimiter': ' ', 'strip': '\' '}
        })
        self.validator.headers['content-security-policy'] = "script-src 'unsafe-inline'; object-src 'unsafe-inline'"

        parse_policy_mock.return_value = [
            "script-src 'unsafe-inline'",
            utils.KeyValueDirective(key='script-src', value=['unsafe-inline'], raw_value="'unsafe-inline'"),
            "object-src 'unsafe-inline'",
            utils.KeyValueDirective(key='object-src', value=['unsafe-inline'], raw_value="'unsafe-inline'")
        ]

        response = self.validator.must_avoid(config, 'content-security-policy')
        self.assertEqual('script-src', response[0].directive)
        self.assertEqual('object-src', response[1].directive)
