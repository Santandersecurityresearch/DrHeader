from drheader import report, utils
from drheader.validators import base

_DELIMITER_TYPE = 'item_delimiter'


class CookieValidator(base.ValidatorBase):

    def __init__(self, cookies):
        self.cookies = cookies

    def validate_exists(self, config, header, directive=None, cookie=None):
        if cookie not in self.cookies:
            severity = config.get('severity', 'high')
            error_type = report.ErrorType.REQUIRED
            return report.ReportItem(severity, error_type, header, cookie=cookie)

    def validate_not_exists(self, config, header, directive=None, cookie=None):
        if cookie in self.cookies:
            severity = config.get('severity', 'high')
            error_type = report.ErrorType.DISALLOWED
            return report.ReportItem(severity, error_type, header, cookie=cookie)

    def validate_value(self, config, header, directive=None):
        raise base.UnsupportedValidationError("'Value' validations are not supported for cookies")

    def validate_value_any_of(self, config, header, directive=None):
        raise base.UnsupportedValidationError("'Value-Any-Of' validations are not supported for cookies")

    def validate_value_one_of(self, config, header, directive=None):
        raise base.UnsupportedValidationError("'Value-One-Of' validations are not supported for cookies")

    def validate_must_avoid(self, config, header, directive=None, cookie=None):
        delimiter = base.get_delimiter(config, _DELIMITER_TYPE)
        disallowed = base.get_expected_values(config, 'must-avoid', delimiter)

        cookie_value = self.cookies[cookie]
        cookie_items = utils.parse_policy(cookie_value, **config['delimiters'], keys_only=True)
        cookie_items = {str(item).lower() for item in cookie_items}

        anomalies = []
        for avoid in disallowed:
            if avoid.lower() in cookie_items:
                anomalies.append(avoid)

        if anomalies:
            severity = config.get('severity', 'high')
            error_type = report.ErrorType.AVOID
            return report.ReportItem(severity, error_type, header, cookie=cookie, value=cookie_value, avoid=disallowed,
                                     anomalies=anomalies)

    def validate_must_contain(self, config, header, directive=None, cookie=None):
        delimiter = base.get_delimiter(config, _DELIMITER_TYPE)
        expected = base.get_expected_values(config, 'must-contain', delimiter)

        cookie_value = self.cookies[cookie]
        cookie_items = utils.parse_policy(cookie_value, **config['delimiters'], keys_only=True)
        cookie_items = {str(item).lower() for item in cookie_items}

        anomalies = []
        for contain in expected:
            if contain.lower() not in cookie_items:
                anomalies.append(contain)

        if anomalies:
            severity = config.get('severity', 'high')
            error_type = report.ErrorType.CONTAIN
            return report.ReportItem(severity, error_type, header, cookie=cookie, value=cookie_value, expected=expected,
                                     anomalies=anomalies, delimiter=delimiter)

    def validate_must_contain_one(self, config, header, directive=None, cookie=None):
        delimiter = base.get_delimiter(config, _DELIMITER_TYPE)
        expected = base.get_expected_values(config, 'must-contain-one', delimiter)

        cookie_value = self.cookies[cookie]
        cookie_items = utils.parse_policy(cookie_value, **config['delimiters'], keys_only=True)
        cookie_items = {str(item).lower() for item in cookie_items}

        if not any(contain.lower() in cookie_items for contain in expected):
            severity = config.get('severity', 'high')
            error_type = report.ErrorType.CONTAIN_ONE
            return report.ReportItem(severity, error_type, header, cookie=cookie, value=cookie_value, expected=expected)
