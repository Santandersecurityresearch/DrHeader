"""Validator module for cookies."""
from drheader import utils
from drheader.report import ErrorType, ReportItem
from drheader.validators import base

_DELIMITER_TYPE = 'item_delimiter'


class CookieValidator(base.ValidatorBase):
    """Validator class for validating cookies.

    Attributes:
        cookies (CaseInsensitiveDict): The cookies to analyse.
    """

    def __init__(self, cookies):
        """Initialises a CookieValidator instance with cookies."""
        self.cookies = cookies

    def exists(self, config, header, **kwargs):
        """See base class."""
        cookie = kwargs['cookie']

        if cookie not in self.cookies:
            severity = config.get('severity', 'high')
            error_type = ErrorType.REQUIRED
            return ReportItem(severity, error_type, header, cookie=cookie)

    def not_exists(self, config, header, **kwargs):
        """See base class."""
        cookie = kwargs['cookie']

        if cookie in self.cookies:
            severity = config.get('severity', 'high')
            error_type = ErrorType.DISALLOWED
            return ReportItem(severity, error_type, header, cookie=cookie)

    def value(self, config, header, **kwargs):
        """Method not supported.

        Raises:
            UnsupportedValidationError: If the method is called.
        """
        raise base.UnsupportedValidationError("'Value' validations are not supported for cookies")

    def value_any_of(self, config, header, **kwargs):
        """Method not supported.

        Raises:
            UnsupportedValidationError: If the method is called.
        """
        raise base.UnsupportedValidationError("'Value-Any-Of' validations are not supported for cookies")

    def value_one_of(self, config, header, **kwargs):
        """Method not supported.

        Raises:
            UnsupportedValidationError: If the method is called.
        """
        raise base.UnsupportedValidationError("'Value-One-Of' validations are not supported for cookies")

    def must_avoid(self, config, header, **kwargs):
        """See base class."""
        cookie = kwargs['cookie']

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
            error_type = ErrorType.AVOID
            return ReportItem(severity, error_type, header, cookie=cookie, value=cookie_value, avoid=disallowed, anomalies=anomalies)  # noqa:E501

    def must_contain(self, config, header, **kwargs):
        """See base class."""
        cookie = kwargs['cookie']

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
            error_type = ErrorType.CONTAIN
            return ReportItem(severity, error_type, header, cookie=cookie, value=cookie_value, expected=expected, anomalies=anomalies, delimiter=delimiter)  # noqa:E501

    def must_contain_one(self, config, header, **kwargs):
        """See base class."""
        cookie = kwargs['cookie']

        delimiter = base.get_delimiter(config, _DELIMITER_TYPE)
        expected = base.get_expected_values(config, 'must-contain-one', delimiter)

        cookie_value = self.cookies[cookie]
        cookie_items = utils.parse_policy(cookie_value, **config['delimiters'], keys_only=True)
        cookie_items = {str(item).lower() for item in cookie_items}

        if not any(contain.lower() in cookie_items for contain in expected):
            severity = config.get('severity', 'high')
            error_type = ErrorType.CONTAIN_ONE
            return ReportItem(severity, error_type, header, cookie=cookie, value=cookie_value, expected=expected)
