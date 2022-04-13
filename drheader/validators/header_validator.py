"""Validator module for headers."""
from drheader import report, utils
from drheader.validators import base

_DELIMITER_TYPE = 'item_delimiter'
_POLICY_HEADERS = ['content-security-policy', 'feature-policy', 'permissions-policy']
_STRIP_HEADERS = ['clear-site-data']


class HeaderValidator(base.ValidatorBase):
    """Validator class for validating headers.

    Attributes:
        headers (CaseInsensitiveDict): The headers to analyse.
    """

    def __init__(self, headers):
        """Initialises a HeaderValidator instance with headers."""
        self.headers = headers

    def validate_exists(self, config, header, directive=None, cookie=None):
        """See base class."""
        if header not in self.headers:
            severity = config.get('severity', 'high')
            error_type = report.ErrorType.REQUIRED
            if 'value' in config:
                delimiter = base.get_delimiter(config, _DELIMITER_TYPE)
                expected = base.get_expected_values(config, 'value', delimiter)
                return report.ReportItem(severity, error_type, header, expected=expected, delimiter=delimiter)
            elif 'value-any-of' in config:
                delimiter = base.get_delimiter(config, _DELIMITER_TYPE)
                expected = base.get_expected_values(config, 'value-any-of', delimiter)
                return report.ReportItem(severity, error_type, header, expected=expected, delimiter=delimiter)
            elif 'value-one-of' in config:
                delimiter = base.get_delimiter(config, _DELIMITER_TYPE)
                expected = base.get_expected_values(config, 'value-one-of', delimiter)
                return report.ReportItem(severity, error_type, header, expected=expected)
            else:
                return report.ReportItem(severity, error_type, header)

    def validate_not_exists(self, config, header, directive=None, cookie=None):
        """See base class."""
        if header in self.headers:
            severity = config.get('severity', 'high')
            error_type = report.ErrorType.DISALLOWED
            return report.ReportItem(severity, error_type, header)

    def validate_value(self, config, header, directive=None):
        """See base class."""
        delimiter = base.get_delimiter(config, _DELIMITER_TYPE)
        expected = base.get_expected_values(config, 'value', delimiter)

        header_value = self.headers[header]
        strip_chars = base.get_delimiter(config, 'strip') if header.lower() in _STRIP_HEADERS else None
        header_items = utils.parse_policy(header_value, item_delimiter=delimiter, strip=strip_chars)

        if config.get('preserve-order'):
            header_items = [item.lower() for item in header_items]
            expected_lower = [item.lower() for item in expected]
        else:
            header_items = {item.lower() for item in header_items}
            expected_lower = {item.lower() for item in expected}

        if header_items != expected_lower:
            severity = config.get('severity', 'high')
            error_type = report.ErrorType.VALUE
            return report.ReportItem(severity, error_type, header, value=header_value, expected=expected,
                                     delimiter=delimiter)

    def validate_value_any_of(self, config, header, directive=None):
        """See base class."""
        delimiter = base.get_delimiter(config, _DELIMITER_TYPE)
        accepted = base.get_expected_values(config, 'value-any-of', delimiter)

        header_value = self.headers[header]
        strip_chars = base.get_delimiter(config, 'strip') if header.lower() in _STRIP_HEADERS else None
        header_items = utils.parse_policy(header_value, item_delimiter=delimiter, strip=strip_chars)

        anomalies = []
        accepted_lower = [item.lower() for item in accepted]
        for item in header_items:
            if item not in accepted_lower:
                anomalies.append(item)

        if anomalies:
            severity = config.get('severity', 'high')
            error_type = report.ErrorType.VALUE_ANY
            return report.ReportItem(severity, error_type, header, value=header_value, expected=accepted,
                                     anomalies=anomalies, delimiter=delimiter)

    def validate_value_one_of(self, config, header, directive=None):
        """See base class."""
        delimiter = base.get_delimiter(config, _DELIMITER_TYPE)
        accepted = base.get_expected_values(config, 'value-one-of', delimiter)

        header_value = self.headers[header]
        strip_chars = base.get_delimiter(config, 'strip') if header.lower() in _STRIP_HEADERS else None

        if header_value.strip(strip_chars).lower() not in {item.lower() for item in accepted}:
            severity = config.get('severity', 'high')
            error_type = report.ErrorType.VALUE_ONE
            return report.ReportItem(severity, error_type, header, value=header_value, expected=accepted)

    def validate_must_avoid(self, config, header, directive=None, cookie=None):
        """See base class."""
        if header.lower() in _POLICY_HEADERS:
            return self._validate_must_avoid_for_policy_header(config, header)

        delimiter = base.get_delimiter(config, _DELIMITER_TYPE)
        disallowed = base.get_expected_values(config, 'must-avoid', delimiter)

        header_value = self._get_cookie(cookie) if cookie else self.headers[header]
        header_items = utils.parse_policy(header_value, **config.get('delimiters', {}), keys_only=True)
        header_items = {str(item).lower() for item in header_items}

        anomalies = []
        for avoid in disallowed:
            if avoid.lower() in header_items:
                anomalies.append(avoid)

        if anomalies:
            severity = config.get('severity', 'high')
            error_type = report.ErrorType.AVOID
            return report.ReportItem(severity, error_type, header, cookie=cookie, value=header_value, avoid=disallowed,
                                     anomalies=anomalies)

    def validate_must_contain(self, config, header, directive=None, cookie=None):
        """See base class."""
        delimiter = base.get_delimiter(config, _DELIMITER_TYPE)
        expected = base.get_expected_values(config, 'must-contain', delimiter)

        header_value = self._get_cookie(cookie) if cookie else self.headers[header]
        header_items = utils.parse_policy(header_value, **config.get('delimiters', {}), keys_only=True)
        header_items = {str(item).lower() for item in header_items}

        anomalies = []
        for contain in expected:
            if contain.lower() not in header_items:
                anomalies.append(contain)

        if anomalies:
            severity = config.get('severity', 'high')
            error_type = report.ErrorType.CONTAIN
            return report.ReportItem(severity, error_type, header, cookie=cookie, value=header_value, expected=expected,
                                     anomalies=anomalies, delimiter=delimiter)

    def validate_must_contain_one(self, config, header, directive=None, cookie=None):
        """See base class."""
        delimiter = base.get_delimiter(config, _DELIMITER_TYPE)
        expected = base.get_expected_values(config, 'must-contain-one', delimiter)

        header_value = self._get_cookie(cookie) if cookie else self.headers[header]
        header_items = utils.parse_policy(header_value, **config.get('delimiters', {}), keys_only=True)
        header_items = {str(item).lower() for item in header_items}

        if not any(contain.lower() in header_items for contain in expected):
            severity = config.get('severity', 'high')
            error_type = report.ErrorType.CONTAIN_ONE
            return report.ReportItem(severity, error_type, header, cookie=cookie, value=header_value, expected=expected)

    def _validate_must_avoid_for_policy_header(self, config, header):
        delimiter = base.get_delimiter(config, _DELIMITER_TYPE)
        disallowed = base.get_expected_values(config, 'must-avoid', delimiter)

        header_value = self.headers[header]
        header_items = []

        directives = utils.parse_policy(header_value, **config['delimiters'])
        for directive in directives:
            try:
                header_items.append(directive.key)
                header_items += [value for value in directive.value]
            except AttributeError:
                header_items.append(directive)
        header_items = {str(item).lower() for item in header_items}

        anomalies, ncd_items, report_items = [], {}, []
        for avoid in disallowed:
            if avoid.lower() in header_items:
                non_compliant_directives = []
                for directive in directives:
                    try:
                        if avoid in directive.value:
                            non_compliant_directives.append(directive)
                    except AttributeError:
                        pass

                if not non_compliant_directives:
                    anomalies.append(avoid)
                else:
                    for ncd in non_compliant_directives:
                        directive, value = ncd.key, ncd.raw_value
                        ncd_item = {
                            'value': value,
                            'anomalies': ncd_items.get(directive, {}).get('anomalies', []) + [avoid]
                        }
                        ncd_items[directive] = ncd_item

        severity = config.get('severity', 'high')
        error_type = report.ErrorType.AVOID

        if anomalies:
            item = report.ReportItem(severity, error_type, header, value=header_value, avoid=disallowed,
                                     anomalies=anomalies)
            report_items.append(item)
        if ncd_items:
            for directive in ncd_items:
                value, anomalies = ncd_items[directive]['value'], ncd_items[directive]['anomalies']
                item = report.ReportItem(severity, error_type, header, directive=directive, value=value,
                                         avoid=disallowed, anomalies=anomalies)
                report_items.append(item)
        return report_items

    def _get_cookie(self, expected):
        for cookie in self.headers['set-cookie']:
            cookie_name = cookie.split('=', 1)[0]
            if cookie_name == expected:
                return cookie
