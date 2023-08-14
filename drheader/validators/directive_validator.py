"""Validator module for directives."""
from drheader import utils
from drheader.report import ErrorType, ReportItem
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

    def exists(self, config, header, **kwargs):
        """See base class."""
        directive = kwargs['directive']

        directives = utils.parse_policy(self.headers[header], **config['delimiters'], keys_only=True)
        directives = {str(item).lower() for item in directives}

        if directive.lower() not in directives:
            severity = config.get('severity', 'high')
            error_type = ErrorType.REQUIRED
            if 'value' in config:
                delimiter = base.get_delimiter(config, _DELIMITER_TYPE)
                expected = base.get_expected_values(config, 'value', delimiter)
                return ReportItem(severity, error_type, header, directive=directive, expected=expected, delimiter=delimiter)  # noqa:E501
            elif 'value-any-of' in config:
                delimiter = base.get_delimiter(config, _DELIMITER_TYPE)
                expected = base.get_expected_values(config, 'value-any-of', delimiter)
                return ReportItem(severity, error_type, header, directive=directive, expected=expected, delimiter=delimiter)  # noqa:E501
            elif 'value-one-of' in config:
                delimiter = base.get_delimiter(config, _DELIMITER_TYPE)
                expected = base.get_expected_values(config, 'value-one-of', delimiter)
                return ReportItem(severity, error_type, header, directive=directive, expected=expected)
            else:
                return ReportItem(severity, error_type, header, directive=directive)

    def not_exists(self, config, header, **kwargs):
        """See base class."""
        directive = kwargs['directive']

        directives = utils.parse_policy(self.headers[header], **config['delimiters'], keys_only=True)
        directives = {str(item).lower() for item in directives}

        if directive.lower() in directives:
            severity = config.get('severity', 'high')
            error_type = ErrorType.DISALLOWED
            return ReportItem(severity, error_type, header, directive=directive)

    def value(self, config, header, **kwargs):
        """See base class."""
        directive = kwargs['directive']

        delimiter = base.get_delimiter(config, _DELIMITER_TYPE)
        expected = base.get_expected_values(config, 'value', delimiter)

        directives = utils.parse_policy(self.headers[header], **config['delimiters'])
        kvd = _get_key_value_directive(directive, directives)
        directive_items = {str(item).lower() for item in kvd.value}

        if directive_items != {item.lower() for item in expected}:
            severity = config.get('severity', 'high')
            error_type = ErrorType.VALUE
            return ReportItem(severity, error_type, header, directive=directive, value=kvd.raw_value, expected=expected, delimiter=delimiter)  # noqa:E501

    def value_any_of(self, config, header, **kwargs):
        """See base class."""
        directive = kwargs['directive']

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
            error_type = ErrorType.VALUE_ANY
            return ReportItem(severity, error_type, header, directive=directive, value=kvd.raw_value, expected=accepted, anomalies=anomalies, delimiter=delimiter)  # noqa:E501

    def value_one_of(self, config, header, **kwargs):
        """See base class."""
        directive = kwargs['directive']

        delimiter = base.get_delimiter(config, _DELIMITER_TYPE)
        accepted = base.get_expected_values(config, 'value-one-of', delimiter)

        directives = utils.parse_policy(self.headers[header], **config['delimiters'])
        kvd = _get_key_value_directive(directive, directives)
        directive_value = kvd.value[0]

        if directive_value not in {item.lower() for item in accepted}:
            severity = config.get('severity', 'high')
            error_type = ErrorType.VALUE_ONE
            return ReportItem(severity, error_type, header, directive=directive, value=kvd.raw_value, expected=accepted)

    def must_avoid(self, config, header, **kwargs):
        """See base class."""
        directive = kwargs['directive']

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
            error_type = ErrorType.AVOID
            return ReportItem(severity, error_type, header, directive=directive, value=kvd.raw_value, avoid=disallowed, anomalies=anomalies)  # noqa:E501

    def must_contain(self, config, header, **kwargs):
        """See base class."""
        directive = kwargs['directive']

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
            error_type = ErrorType.CONTAIN
            return ReportItem(severity, error_type, header, directive=directive, value=kvd.raw_value, expected=expected, anomalies=anomalies, delimiter=delimiter)  # noqa:E501

    def must_contain_one(self, config, header, **kwargs):
        """See base class."""
        directive = kwargs['directive']

        delimiter = base.get_delimiter(config, _DELIMITER_TYPE)
        expected = base.get_expected_values(config, 'must-contain-one', delimiter)

        directives = utils.parse_policy(self.headers[header], **config['delimiters'])
        kvd = _get_key_value_directive(directive, directives)
        directive_items = {str(item).lower() for item in kvd.value}

        if not any(contain.lower() in directive_items for contain in expected):
            severity = config.get('severity', 'high')
            error_type = ErrorType.CONTAIN_ONE
            return ReportItem(severity, error_type, header, directive=directive, value=kvd.raw_value, expected=expected)


def _get_key_value_directive(directive_name, directives_list):
    for directive in directives_list:
        if isinstance(directive, utils.KeyValueDirective) and directive.key.lower() == directive_name.lower():
            return directive
