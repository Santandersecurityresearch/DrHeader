"""Validator module for directives."""
from drheader import report, utils
from drheader.validators import base

_DELIMITER_TYPE = 'value_delimiter'


class DirectiveValidator(base.ValidatorBase):
    """Validator class for validating directives.

    Attributes:
        headers (CaseInsensitiveDict): The headers to analyse.
    """

    def __init__(self, headers):
        """Initialises a DirectiveValidator instance with headers."""
        self.headers = headers

    def validate_exists(self, config, header, directive=None, cookie=None):
        """See base class."""
        directives = utils.parse_policy(self.headers[header], **config['delimiters'], keys_only=True)
        directives = {str(item).lower() for item in directives}

        if directive.lower() not in directives:
            severity = config.get('severity', 'high')
            error_type = report.ErrorType.REQUIRED
            if 'value' in config:
                delimiter = base.get_delimiter(config, _DELIMITER_TYPE)
                expected = base.get_expected_values(config, 'value', delimiter)
                return report.ReportItem(severity, error_type, header, directive=directive, expected=expected,
                                         delimiter=delimiter)
            elif 'value-any-of' in config:
                delimiter = base.get_delimiter(config, _DELIMITER_TYPE)
                expected = base.get_expected_values(config, 'value-any-of', delimiter)
                return report.ReportItem(severity, error_type, header, directive=directive, expected=expected,
                                         delimiter=delimiter)
            elif 'value-one-of' in config:
                delimiter = base.get_delimiter(config, _DELIMITER_TYPE)
                expected = base.get_expected_values(config, 'value-one-of', delimiter)
                return report.ReportItem(severity, error_type, header, directive=directive, expected=expected)
            else:
                return report.ReportItem(severity, error_type, header, directive=directive)

    def validate_not_exists(self, config, header, directive=None, cookie=None):
        """See base class."""
        directives = utils.parse_policy(self.headers[header], **config['delimiters'], keys_only=True)
        directives = {str(item).lower() for item in directives}

        if directive.lower() in directives:
            severity = config.get('severity', 'high')
            error_type = report.ErrorType.DISALLOWED
            return report.ReportItem(severity, error_type, header, directive=directive)

    def validate_value(self, config, header, directive=None):
        """See base class."""
        delimiter = base.get_delimiter(config, _DELIMITER_TYPE)
        expected = base.get_expected_values(config, 'value', delimiter)

        directives = utils.parse_policy(self.headers[header], **config['delimiters'])
        kvd = _get_key_value_directive(directive, directives)
        directive_items = {str(item).lower() for item in kvd.value}

        if directive_items != {item.lower() for item in expected}:
            severity = config.get('severity', 'high')
            error_type = report.ErrorType.VALUE
            return report.ReportItem(severity, error_type, header, directive=directive, value=kvd.raw_value,
                                     expected=expected, delimiter=delimiter)

    def validate_value_any_of(self, config, header, directive=None):
        """See base class."""
        delimiter = base.get_delimiter(config, _DELIMITER_TYPE)
        accepted = base.get_expected_values(config, 'value-any-of', delimiter)

        directives = utils.parse_policy(self.headers[header], **config['delimiters'])
        kvd = _get_key_value_directive(directive, directives)
        directive_items = {str(item).lower() for item in kvd.value}

        anomalies = []
        accepted_lower = [item.lower() for item in accepted]
        for item in directive_items:
            if item not in accepted_lower:
                anomalies.append(item)

        if anomalies:
            severity = config.get('severity', 'high')
            error_type = report.ErrorType.VALUE_ANY
            return report.ReportItem(severity, error_type, header, directive=directive, value=kvd.raw_value,
                                     expected=accepted, anomalies=anomalies, delimiter=delimiter)

    def validate_value_one_of(self, config, header, directive=None):
        """See base class."""
        delimiter = base.get_delimiter(config, _DELIMITER_TYPE)
        accepted = base.get_expected_values(config, 'value-one-of', delimiter)

        directives = utils.parse_policy(self.headers[header], **config['delimiters'])
        kvd = _get_key_value_directive(directive, directives)
        directive_value = kvd.value[0]

        if directive_value not in {item.lower() for item in accepted}:
            severity = config.get('severity', 'high')
            error_type = report.ErrorType.VALUE_ONE
            return report.ReportItem(severity, error_type, header, directive=directive, value=kvd.raw_value,
                                     expected=accepted)

    def validate_must_avoid(self, config, header, directive=None, cookie=None):
        """See base class."""
        delimiter = base.get_delimiter(config, _DELIMITER_TYPE)
        disallowed = base.get_expected_values(config, 'must-avoid', delimiter)

        directives = utils.parse_policy(self.headers[header], **config['delimiters'])
        kvd = _get_key_value_directive(directive, directives)
        directive_items = {str(item).lower() for item in kvd.value}

        anomalies = []
        for avoid in disallowed:
            if avoid.lower() in directive_items:
                anomalies.append(avoid)

        if anomalies:
            severity = config.get('severity', 'high')
            error_type = report.ErrorType.AVOID
            return report.ReportItem(severity, error_type, header, directive=directive, value=kvd.raw_value,
                                     avoid=disallowed, anomalies=anomalies)

    def validate_must_contain(self, config, header, directive=None, cookie=None):
        """See base class."""
        delimiter = base.get_delimiter(config, _DELIMITER_TYPE)
        expected = base.get_expected_values(config, 'must-contain', delimiter)

        directives = utils.parse_policy(self.headers[header], **config['delimiters'])
        kvd = _get_key_value_directive(directive, directives)
        directive_items = {str(item).lower() for item in kvd.value}

        anomalies = []
        for contain in expected:
            if contain.lower() not in directive_items:
                anomalies.append(contain)

        if anomalies:
            severity = config.get('severity', 'high')
            error_type = report.ErrorType.CONTAIN
            return report.ReportItem(severity, error_type, header, directive=directive, value=kvd.raw_value,
                                     expected=expected, anomalies=anomalies, delimiter=delimiter)

    def validate_must_contain_one(self, config, header, directive=None, cookie=None):
        """See base class."""
        delimiter = base.get_delimiter(config, _DELIMITER_TYPE)
        expected = base.get_expected_values(config, 'must-contain-one', delimiter)

        directives = utils.parse_policy(self.headers[header], **config['delimiters'])
        kvd = _get_key_value_directive(directive, directives)
        directive_items = {str(item).lower() for item in kvd.value}

        if not any(contain.lower() in directive_items for contain in expected):
            severity = config.get('severity', 'high')
            error_type = report.ErrorType.CONTAIN_ONE
            return report.ReportItem(severity, error_type, header, directive=directive, value=kvd.raw_value,
                                     expected=expected)


def _get_key_value_directive(directive_name, directives_list):
    for directive in directives_list:
        if isinstance(directive, utils.KeyValueDirective) and directive.key.lower() == directive_name.lower():
            return directive
