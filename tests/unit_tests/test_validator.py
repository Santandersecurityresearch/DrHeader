from unittest import mock

import unittest2
from requests.structures import CaseInsensitiveDict

from drheader import validator
from drheader.report import ReportItem, ErrorType
from drheader.utils import KeyValueDirective


class TestValidator(unittest2.TestCase):

    def setUp(self):
        self.addTypeEqualityFunc(ReportItem, self.assert_report_items_equal)

    def assert_report_items_equal(self, expected_report_item, observed_report_item, msg=None):
        does_validate = True

        for field in expected_report_item._asdict():
            expected = getattr(expected_report_item, field)
            observed = getattr(observed_report_item, field)
            if not expected == observed:
                msg += f"\tNon-matching values for field '{field}'. Expected: '{expected}' Observed: '{observed}'\n"
                does_validate = False
        if not does_validate:
            raise self.failureException(msg)

    def test_validate_value__ok(self):
        config = CaseInsensitiveDict({'required': True, 'value': ['no-store', 'max-age=0']})

        response = validator.validate_value(config, 'no-store, max-age=0', 'cache-control')
        self.assertIsNone(response)

    def test_validate_value__unexpected_item_in_header_value__ko(self):
        config = CaseInsensitiveDict({'required': True, 'value': ['no-store', 'max-age=0']})
        header_value = 'no-store, max-age=0, must-revalidate'

        response = validator.validate_value(config, header_value, 'cache-control')
        expected = ReportItem('high', ErrorType.VALUE, 'cache-control', value=header_value, expected=['no-store', 'max-age=0'], delimiter=',')
        self.assertEqual(expected, response, msg='The report items are not equal:\n')

    def test_validate_value__missing_item_from_header_value__ko(self):
        config = CaseInsensitiveDict({'required': True, 'value': ['max-age=31536000', 'includesubdomains']})
        header_value = 'max-age=31536000'

        response = validator.validate_value(config, header_value, 'strict-transport-security')
        expected = ReportItem('high', ErrorType.VALUE, 'strict-transport-security', value=header_value, expected=['max-age=31536000', 'includesubdomains'], delimiter=';')
        self.assertEqual(expected, response, msg='The report items are not equal:\n')

    def test_validate_value__enforced_order_not_correct__ko(self):
        config = CaseInsensitiveDict({'required': True, 'value': ['no-referrer', 'strict-origin-when-cross-origin'], 'preserve-order': True})
        header_value = 'strict-origin-when-cross-origin, no-referrer'

        response = validator.validate_value(config, header_value, 'referrer-policy')
        expected = ReportItem('high', ErrorType.VALUE, 'referrer-policy', value=header_value, expected=['no-referrer', 'strict-origin-when-cross-origin'], delimiter=',')
        self.assertEqual(expected, response, msg='The report items are not equal:\n')

    def test_validate_value_any_of__ok(self):
        config = CaseInsensitiveDict({'required': True, 'value-any-of': ['no-referrer', 'same-origin', 'strict-origin']})

        response = validator.validate_value_any_of(config, 'no-referrer, same-origin', 'referrer-policy')
        self.assertIsNone(response)

    def test_validate_value_any_of__non_permitted_item_in_header_value__ko(self):
        config = CaseInsensitiveDict({'required': True, 'value-any-of': ['no-referrer', 'same-origin', 'strict-origin']})
        header_value = 'no-referrer, strict-origin-when-cross-origin'

        response = validator.validate_value_any_of(config, header_value, 'referrer-policy')
        expected = ReportItem('high', ErrorType.VALUE_ANY, 'referrer-policy', value=header_value, expected=['no-referrer', 'same-origin', 'strict-origin'], delimiter=',', anomalies=['strict-origin-when-cross-origin'])
        self.assertEqual(expected, response, msg='The report items are not equal:\n')

    def test_validate_value_one_of__ok(self):
        config = CaseInsensitiveDict({'required': True, 'value-one-of': ['deny', 'sameorigin']})

        response = validator.validate_value_one_of(config, 'deny', 'x-frame-options')
        self.assertIsNone(response)

    def test_validate_value_one_of__non_permitted_header_value__ko(self):
        config = CaseInsensitiveDict({'required': True, 'value-one-of': ['deny', 'sameorigin']})
        header_value = 'allow-from https://example.com'

        response = validator.validate_value_one_of(config, header_value, 'x-frame-options')
        expected = ReportItem('high', ErrorType.VALUE_ONE, 'x-frame-options', value=header_value, expected=['deny', 'sameorigin'])
        self.assertEqual(expected, response, msg='The report items are not equal:\n')

    def test_validate_value_one_of__too_many_items_in_header_value__ko(self):
        config = CaseInsensitiveDict({'required': True, 'value-one-of': ['deny', 'sameorigin']})
        header_value = 'deny sameorigin'

        response = validator.validate_value_one_of(config, header_value, 'x-frame-options')
        expected = ReportItem('high', ErrorType.VALUE_ONE, 'x-frame-options', value=header_value, expected=['deny', 'sameorigin'])
        self.assertEqual(expected, response, msg='The report items are not equal:\n')

    @mock.patch('drheader.validator.parse_policy')
    def test_validate_must_avoid__standalone_directive__ok(self, parse_policy_mock):
        config = CaseInsensitiveDict({'required': True, 'must-avoid': ['no-cache', 'private', 'public']})
        parse_policy_mock.return_value = ['no-store', 'max-age']

        response = validator.validate_must_avoid(config, 'no-store, max-age=0', 'cache-control')
        self.assertIsNone(response)

    @mock.patch('drheader.validator.parse_policy')
    def test_validate_must_avoid__standalone_directive__ko(self, parse_policy_mock):
        config = CaseInsensitiveDict({'required': True, 'must-avoid': ['no-cache', 'private', 'public']})
        header_value = 'no-cache, max-age=0'
        parse_policy_mock.return_value = ['no-cache', 'max-age']

        response = validator.validate_must_avoid(config, header_value, 'cache-control')
        expected = ReportItem('medium', ErrorType.AVOID, 'cache-control', value=header_value, avoid=['no-cache', 'private', 'public'], anomalies=['no-cache'])
        self.assertEqual(expected, response, msg='The report items are not equal:\n')

    @mock.patch('drheader.validator.parse_policy')
    def test_validate_must_avoid__key_for_key_value_directive__ok(self, parse_policy_mock):
        config = CaseInsensitiveDict({'required': True, 'must-avoid': ['expires', 'max-age']})
        parse_policy_mock.return_value = ['sid', 'httponly', 'secure']

        response = validator.validate_must_avoid(config, 'sid=47383373; httponly; secure', 'set-cookie')
        self.assertIsNone(response)

    @mock.patch('drheader.validator.parse_policy')
    def test_validate_must_avoid__key_for_key_value_directive__ko(self, parse_policy_mock):
        config = CaseInsensitiveDict({'required': True, 'must-avoid': ['expires', 'max-age']})
        header_value = 'sid=47383373; httponly; secure; max-age=2592000'
        parse_policy_mock.return_value = ['sid', 'httponly', 'secure', 'max-age']

        response = validator.validate_must_avoid(config, header_value, 'set-cookie')
        expected = ReportItem('medium', ErrorType.AVOID, 'set-cookie', value=header_value, avoid=['expires', 'max-age'], anomalies=['max-age'])
        self.assertEqual(expected, response, msg='The report items are not equal:\n')

    @mock.patch('drheader.validator.parse_policy')
    def test_validate_must_avoid_for_policy_header__standalone_directive__ok(self, parse_policy_mock):
        config = CaseInsensitiveDict({'required': True, 'must-avoid': ['block-all-mixed-content']})
        parse_policy_mock.return_value = [KeyValueDirective(key='default-src', value=['none'], raw_value="'none'")]

        response = validator.validate_must_avoid(config, "default-src 'none'", 'content-security-policy')
        self.assertEqual(0, len(response))

    @mock.patch('drheader.validator.parse_policy')
    def test_validate_must_avoid_for_policy_header__standalone_directive__ko(self, parse_policy_mock):
        config = CaseInsensitiveDict({'required': True, 'must-avoid': ['block-all-mixed-content']})
        header_value = "upgrade-insecure-requests; block-all-mixed-content"
        parse_policy_mock.return_value = ['upgrade-insecure-requests', 'block-all-mixed-content']

        response = validator.validate_must_avoid(config, header_value, 'content-security-policy')[0]
        expected = ReportItem('medium', ErrorType.AVOID, 'content-security-policy', value=header_value, avoid=['block-all-mixed-content'], anomalies=['block-all-mixed-content'])
        self.assertEqual(expected, response, msg='The report items are not equal:\n')

    @mock.patch('drheader.validator.parse_policy')
    def test_validate_must_avoid_for_policy_header__key_for_key_value_directive__ok(self, parse_policy_mock):
        config = CaseInsensitiveDict({'required': True, 'must-avoid': ['frame-src']})
        parse_policy_mock.return_value = [KeyValueDirective(key='default-src', value=['none'], raw_value="'none'")]

        response = validator.validate_must_avoid(config, "default-src 'none'", 'content-security-policy')
        self.assertEqual(0, len(response))

    @mock.patch('drheader.validator.parse_policy')
    def test_validate_must_avoid_for_policy_header__key_for_key_value_directive__ko(self, parse_policy_mock):
        config = CaseInsensitiveDict({'required': True, 'must-avoid': ['frame-src']})
        header_value = "default-src 'none'; frame-src https://example.com"
        parse_policy_mock.return_value = [
            KeyValueDirective(key='default-src', value=['none'], raw_value="'none'"),
            KeyValueDirective(key='frame-src', value=['https://example.com'], raw_value='https://example.com')
        ]

        response = validator.validate_must_avoid(config, header_value, 'content-security-policy')[0]
        expected = ReportItem('medium', ErrorType.AVOID, 'content-security-policy', value=header_value, avoid=['frame-src'], anomalies=['frame-src'])
        self.assertEqual(expected, response, msg='The report items are not equal:\n')

    @mock.patch('drheader.validator.parse_policy')
    def test_validate_must_avoid_for_policy_header__value_for_key_value_directive__ok(self, parse_policy_mock):
        config = CaseInsensitiveDict({'required': True, 'must-avoid': ['unsafe-eval']})
        parse_policy_mock.return_value = [KeyValueDirective(key='default-src', value=['none'], raw_value="'none'")]

        response = validator.validate_must_avoid(config, "default-src 'none'", 'content-security-policy')
        self.assertEqual(0, len(response))

    @mock.patch('drheader.validator.parse_policy')
    def test_validate_must_avoid_for_policy_header__value_for_key_value_directive__ko(self, parse_policy_mock):
        config = CaseInsensitiveDict({'required': True, 'must-avoid': ['unsafe-eval']})
        header_value = "default-src 'none'; script-src 'unsafe-eval'"
        parse_policy_mock.return_value = [
            KeyValueDirective(key='default-src', value=['none'], raw_value="'none'"),
            KeyValueDirective(key='script-src', value=['unsafe-eval'], raw_value="'unsafe-eval'")
        ]

        response = validator.validate_must_avoid(config, header_value, 'content-security-policy')[0]
        expected = ReportItem('medium', ErrorType.AVOID, 'content-security-policy', directive='script-src', value="'unsafe-eval'", avoid=['unsafe-eval'], anomalies=['unsafe-eval'])
        self.assertEqual(expected, response, msg='The report items are not equal:\n')

    @mock.patch('drheader.validator.parse_policy')
    def test_validate_must_avoid_for_policy_header__should_return_all_non_compliant_directives(self, parse_policy_mock):
        config = CaseInsensitiveDict({'required': True, 'must-avoid': ['unsafe-inline']})
        parse_policy_mock.return_value = [
            KeyValueDirective(key='default-src', value=['none'], raw_value="'none'"),
            KeyValueDirective(key='script-src', value=['unsafe-inline'], raw_value="'unsafe-inline'"),
            KeyValueDirective(key='object-src', value=['unsafe-inline'], raw_value="'unsafe-inline'")
        ]

        response = validator.validate_must_avoid(config, "default-src 'none'; script-src 'unsafe-inline'; object-src 'unsafe-inline'", 'content-security-policy')
        self.assertEqual('script-src', response[0].directive)
        self.assertEqual('object-src', response[1].directive)

    @mock.patch('drheader.validator.parse_policy')
    def test_validate_must_contain__standalone_directive__ok(self, parse_policy_mock):
        config = CaseInsensitiveDict({'required': 'optional', 'must-contain': ['httponly', 'secure']})
        parse_policy_mock.return_value = ['sid', 'httponly', 'secure']

        response = validator.validate_must_contain(config, 'sid=47383373; httponly; secure', 'set-cookie')
        self.assertIsNone(response)

    @mock.patch('drheader.validator.parse_policy')
    def test_validate_must_contain__standalone_directive__ko(self, parse_policy_mock):
        config = CaseInsensitiveDict({'required': 'optional', 'must-contain': ['httponly', 'secure']})
        header_value = 'sid=47383373; httponly'
        parse_policy_mock.return_value = ['sid', 'httponly']

        response = validator.validate_must_contain(config, header_value, 'set-cookie')
        expected = ReportItem('medium', ErrorType.CONTAIN, 'set-cookie', value=header_value, expected=['httponly', 'secure'], anomalies=['secure'], delimiter=';')
        self.assertEqual(expected, response, msg='The report items are not equal:\n')

    @mock.patch('drheader.validator.parse_policy')
    def test_validate_must_contain__key_value_directive__ok(self, parse_policy_mock):
        config = CaseInsensitiveDict({'required': 'optional', 'must-contain': ['max-age=0']})
        parse_policy_mock.return_value = ['sid', 'httponly', 'secure', 'max-age']

        response = validator.validate_must_contain(config, 'sid=47383373; httponly; secure; max-age=0', 'set-cookie')
        self.assertIsNone(response)

    @mock.patch('drheader.validator.parse_policy')
    def test_validate_must_contain__key_value_directive__ko(self, parse_policy_mock):
        config = CaseInsensitiveDict({'required': 'optional', 'must-contain': ['max-age=0']})
        header_value = 'sid=47383373; httponly; secure'
        parse_policy_mock.return_value = ['sid', 'httponly', 'secure']

        response = validator.validate_must_contain(config, header_value, 'set-cookie')
        expected = ReportItem('medium', ErrorType.CONTAIN, 'set-cookie', value=header_value, expected=['max-age=0'], anomalies=['max-age=0'], delimiter=';')
        self.assertEqual(expected, response, msg='The report items are not equal:\n')

    @mock.patch('drheader.validator.parse_policy')
    def test_validate_must_contain__key_for_key_value_directive__ok(self, parse_policy_mock):
        config = CaseInsensitiveDict({'required': 'optional', 'must-contain': ['max-age']})
        parse_policy_mock.return_value = ['sid', 'httponly', 'max-age']

        response = validator.validate_must_contain(config, 'sid=47383373; httponly; max-age=0', 'set-cookie')
        self.assertIsNone(response)

    @mock.patch('drheader.validator.parse_policy')
    def test_validate_must_contain__key_for_key_value_directive__ko(self, parse_policy_mock):
        config = CaseInsensitiveDict({'required': 'optional', 'must-contain': ['max-age']})
        header_value = 'sid=47383373; httponly'
        parse_policy_mock.return_value = ['sid', 'httponly']

        response = validator.validate_must_contain(config, header_value, 'set-cookie')
        expected = ReportItem('medium', ErrorType.CONTAIN, 'set-cookie', value=header_value, expected=['max-age'], anomalies=['max-age'], delimiter=';')
        self.assertEqual(expected, response, msg='The report items are not equal:\n')

    @mock.patch('drheader.validator.parse_policy')
    def test_validate_must_contain_one__standalone_directive__ok(self, parse_policy_mock):
        config = CaseInsensitiveDict({'required': True, 'must-contain-one': ['no-cache', 'must-revalidate']})
        parse_policy_mock.return_value = ['public', 'max-age', 'must-revalidate']

        response = validator.validate_must_contain_one(config, 'public, max-age=0, must-revalidate', 'cache-control')
        self.assertIsNone(response)

    @mock.patch('drheader.validator.parse_policy')
    def test_validate_must_contain_one__standalone_directive__ko(self, parse_policy_mock):
        config = CaseInsensitiveDict({'required': True, 'must-contain-one': ['no-cache', 'must-revalidate']})
        header_value = 'public, max-age=604800'
        parse_policy_mock.return_value = ['public', 'max-age']

        response = validator.validate_must_contain_one(config, header_value, 'cache-control')
        expected = ReportItem('high', ErrorType.CONTAIN_ONE, 'cache-control', value=header_value, expected=['no-cache', 'must-revalidate'])
        self.assertEqual(expected, response, msg='The report items are not equal:\n')

    @mock.patch('drheader.validator.parse_policy')
    def test_validate_must_contain_one__key_for_key_value_directive__ok(self, parse_policy_mock):
        config = CaseInsensitiveDict({'required': True, 'must-contain-one': ['expires', 'max-age']})
        parse_policy_mock.return_value = ['sid', 'httponly', 'max-age']

        response = validator.validate_must_contain_one(config, 'sid=47383373; httponly; max-age=0', 'set-cookie')
        self.assertIsNone(response)

    @mock.patch('drheader.validator.parse_policy')
    def test_validate_must_contain_one__key_for_key_value_directive__ko(self, parse_policy_mock):
        config = CaseInsensitiveDict({'required': True, 'must-contain-one': ['expires', 'max-age']})
        header_value = 'sid=47383373; httponly'
        parse_policy_mock.return_value = ['sid', 'httponly']

        response = validator.validate_must_contain_one(config, header_value, 'set-cookie')
        expected = ReportItem('high', ErrorType.CONTAIN_ONE, 'set-cookie', value=header_value, expected=['expires', 'max-age'])
        self.assertEqual(expected, response, msg='The report items are not equal:\n')
