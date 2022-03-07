import unittest2
from requests.structures import CaseInsensitiveDict

from drheader import validator
from drheader.report import ReportItem, ErrorType


class TestValidator(unittest2.TestCase):

    def setUp(self):
        self.addTypeEqualityFunc(ReportItem, self.assert_report_items_equal)

    def assert_report_items_equal(self, expected_report_item, observed_report_item, msg=None):
        does_validate = True

        for field, value in vars(expected_report_item).items():
            expected = getattr(expected_report_item, field)
            observed = getattr(observed_report_item, field)
            if not expected == observed:
                msg += f"\tNon-matching values for field '{field}'. Expected: '{expected}' Observed: '{observed}'\n"
                does_validate = False
        if not does_validate:
            raise self.failureException(msg)

    def test_validate_value_unexpected_items_in_header_value_ko(self):
        config = CaseInsensitiveDict({'required': True, 'value': ['no-store', 'max-age=0']})
        header_value = 'private, no-store, max-age=0'

        response = validator.validate_value(config, header_value, 'cache-control')
        expected = ReportItem('high', ErrorType.VALUE, 'cache-control', value=header_value, expected=['no-store', 'max-age=0'], delimiter=',')
        self.assertEqual(expected, response, msg='The report items are not equal:\n')

    def test_validate_value_missing_items_from_header_value_ko(self):
        config = CaseInsensitiveDict({'required': True, 'value': ['no-store', 'max-age=0']})
        header_value = 'no-store'

        response = validator.validate_value(config, header_value, 'cache-control')
        expected = ReportItem('high', ErrorType.VALUE, 'cache-control', value=header_value, expected=['no-store', 'max-age=0'], delimiter=',')
        self.assertEqual(expected, response, msg='The report items are not equal:\n')

    def test_validate_value_one_of_non_matching_header_value_ko(self):
        config = CaseInsensitiveDict({'required': True, 'value-one-of': ['DENY', 'SAMEORIGIN']})
        header_value = 'ALLOW-FROM https://example.com'

        response = validator.validate_value_one_of(config, header_value, 'x-frame-options')
        expected = ReportItem('high', ErrorType.VALUE, 'x-frame-options', value=header_value, expected_one=['DENY', 'SAMEORIGIN'])
        self.assertEqual(expected, response, msg='The report items are not equal:\n')

    def test_validate_value_one_of_additional_items_in_header_value_ko(self):
        config = CaseInsensitiveDict({'required': True, 'value-one-of': ['DENY', 'SAMEORIGIN']})
        header_value = 'DENY SAMEORIGIN'

        response = validator.validate_value_one_of(config, header_value, 'x-frame-options')
        expected = ReportItem('high', ErrorType.VALUE, 'x-frame-options', value=header_value, expected_one=['DENY', 'SAMEORIGIN'])
        self.assertEqual(expected, response, msg='The report items are not equal:\n')

    def test_validate_must_avoid_standalone_directive_ko(self):
        config = CaseInsensitiveDict({'required': True, 'must-avoid': ['unsafe-url']})
        header_value = 'unsafe-url'

        response = validator.validate_must_avoid(config, header_value, 'referrer-policy')[0]
        expected = ReportItem('medium', ErrorType.AVOID, 'referrer-policy', value=header_value, avoid=['unsafe-url'], anomaly='unsafe-url')
        self.assertEqual(expected, response, msg='The report items are not equal:\n')

    def test_validate_must_avoid_key_value_directive_ko(self):
        config = CaseInsensitiveDict({'required': 'optional', 'must-avoid': ['SameSite=None']})
        header_value = 'sid=47383373; HttpOnly; SameSite=None'

        response = validator.validate_must_avoid(config, header_value, 'set-cookie')[0]
        expected = ReportItem('medium', ErrorType.AVOID, 'set-cookie', value=header_value, avoid=['SameSite=None'], anomaly='SameSite=None')
        self.assertEqual(expected, response, msg='The report items are not equal:\n')

    def test_validate_must_avoid_key_for_key_value_directive_ko(self):
        config = CaseInsensitiveDict({'required': True, 'must-avoid': ['ALLOW-FROM']})
        header_value = 'ALLOW-FROM https://example.com'

        response = validator.validate_must_avoid(config, header_value, 'x-frame-options')[0]
        expected = ReportItem('medium', ErrorType.AVOID, 'x-frame-options', value=header_value, avoid=['ALLOW-FROM'], anomaly='ALLOW-FROM')
        self.assertEqual(expected, response, msg='The report items are not equal:\n')

    def test_validate_must_avoid_for_policy_header_standalone_directive_ko(self):
        config = CaseInsensitiveDict({'required': True, 'must-avoid': ['block-all-mixed-content']})
        header_value = "default-src 'none'; upgrade-insecure-requests; block-all-mixed-content"

        response = validator.validate_must_avoid(config, header_value, 'content-security-policy')[0]
        expected = ReportItem('medium', ErrorType.AVOID, 'content-security-policy', value=header_value, avoid=['block-all-mixed-content'], anomaly='block-all-mixed-content')
        self.assertEqual(expected, response, msg='The report items are not equal:\n')

    def test_validate_must_avoid_for_policy_header_key_for_key_value_directive_ko(self):
        config = CaseInsensitiveDict({'required': True, 'must-avoid': ['script-src']})
        header_value = "default-src 'none'; script-src https://example.com"

        response = validator.validate_must_avoid(config, header_value, 'content-security-policy')[0]
        expected = ReportItem('medium', ErrorType.AVOID, 'content-security-policy', value=header_value, avoid=['script-src'], anomaly='script-src')
        self.assertEqual(expected, response, msg='The report items are not equal:\n')

    def test_validate_must_avoid_for_policy_header_value_for_key_value_directive_ko(self):
        config = CaseInsensitiveDict({'required': True, 'must-avoid': ['unsafe-eval']})
        header_value = "default-src 'none'; script-src 'unsafe-eval'"

        response = validator.validate_must_avoid(config, header_value, 'content-security-policy')[0]
        expected = ReportItem('medium', ErrorType.AVOID, 'content-security-policy', directive='script-src', value="'unsafe-eval'", avoid=['unsafe-eval'], anomaly='unsafe-eval')
        self.assertEqual(expected, response, msg='The report items are not equal:\n')

    def test_validate_must_avoid_for_policy_header_should_return_all_non_compliant_directives(self):
        config = CaseInsensitiveDict({'required': True, 'must-avoid': ['unsafe-inline']})
        header_value = "default-src 'none'; script-src 'unsafe-inline'; object-src 'unsafe-inline'"

        response = validator.validate_must_avoid(config, header_value, 'content-security-policy')

        self.assertEqual(2, len(response))
        self.assertEqual('script-src', response[0].directive)
        self.assertEqual('object-src', response[1].directive)

    def test_validate_must_contain_standalone_directive_ko(self):
        config = CaseInsensitiveDict({'required': 'optional', 'must-contain': ['secure']})
        header_value = 'sid=47383373; HttpOnly'

        response = validator.validate_must_contain(config, header_value, 'set-cookie')[0]
        expected = ReportItem('medium', ErrorType.CONTAIN, 'set-cookie', value=header_value, expected=['secure'], anomaly='secure', delimiter=';')
        self.assertEqual(expected, response, msg='The report items are not equal:\n')

    def test_validate_must_contain_key_value_directive_ko(self):
        config = CaseInsensitiveDict({'required': True, 'must-contain': ['max-age=0']})
        header_value = 'no-cache, must-revalidate'

        response = validator.validate_must_contain(config, header_value, 'cache-control')[0]
        expected = ReportItem('medium', ErrorType.CONTAIN, 'cache-control', value=header_value, expected=['max-age=0'], anomaly='max-age=0', delimiter=',')
        self.assertEqual(expected, response, msg='The report items are not equal:\n')

    def test_validate_must_contain_key_for_key_value_directive_ok(self):
        config = CaseInsensitiveDict({'required': 'optional', 'must-contain': ['max-age']})
        header_value = 'sid=47383373; HttpOnly; Max-Age=0'

        response = validator.validate_must_contain(config, header_value, 'set-cookie')
        self.assertEqual(0, len(response))

    def test_validate_must_contain_key_for_key_value_directive_ko(self):
        config = CaseInsensitiveDict({'required': 'optional', 'must-contain': ['max-age']})
        header_value = 'sid=47383373; HttpOnly'

        response = validator.validate_must_contain(config, header_value, 'set-cookie')[0]
        expected = ReportItem('medium', ErrorType.CONTAIN, 'set-cookie', value=header_value, expected=['max-age'], anomaly='max-age', delimiter=';')
        self.assertEqual(expected, response, msg='The report items are not equal:\n')

    def test_validate_must_contain_one_standalone_directive_ko(self):
        config = CaseInsensitiveDict({'required': True, 'must-contain-one': ['no-cache', 'must-revalidate']})
        header_value = 'public, max-age=604800'

        response = validator.validate_must_contain_one(config, header_value, 'cache-control')
        expected = ReportItem('high', ErrorType.CONTAIN_ONE, 'cache-control', value=header_value, expected_one=['no-cache', 'must-revalidate'])
        self.assertEqual(expected, response, msg='The report items are not equal:\n')

    def test_validate_must_contain_one_key_for_key_value_directive_ok(self):
        config = CaseInsensitiveDict({'required': 'optional', 'must-contain-one': ['max-age', 'expires']})
        header_value = 'sid=47383373; HttpOnly; Max-Age=0'

        response = validator.validate_must_contain_one(config, header_value, 'set-cookie')
        self.assertIsNone(response)

    def test_validate_must_contain_one_key_for_key_value_directive_ko(self):
        config = CaseInsensitiveDict({'required': 'optional', 'must-contain-one': ['max-age', 'expires']})
        header_value = 'sid=47383373; HttpOnly'

        response = validator.validate_must_contain_one(config, header_value, 'set-cookie')
        expected = ReportItem('high', ErrorType.CONTAIN_ONE, 'set-cookie', value=header_value, expected_one=['max-age', 'expires'])
        self.assertEqual(expected, response, msg='The report items are not equal:\n')
