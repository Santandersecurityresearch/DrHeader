from enum import Enum


class ErrorType(Enum):
    AVOID = 'Must-Avoid directive included'
    CONTAIN = 'Must-Contain directive missed. All of the expected items were expected'
    CONTAIN_ONE = 'Must-Contain-One directive missed. At least one of the expected items was expected'
    DISALLOWED = '{} should not be returned'
    REQUIRED = '{} not included in response'
    VALUE = 'Value does not match security policy. All of the expected items were expected'
    VALUE_ANY = 'Value does not match security policy. At least one of the expected items was expected'
    VALUE_ONE = 'Value does not match security policy. Exactly one of the expected items was expected'


class ReportItem:

    def __init__(self, severity, error_type, header, directive=None, value=None, avoid=None, expected=None,
                 anomalies=None, delimiter=None):
        self.severity = severity
        self.error_type = error_type
        self.header = header
        self.directive = directive
        self.value = value
        self.avoid = avoid
        self.expected = expected
        self.anomalies = anomalies
        self.delimiter = delimiter


class Reporter:

    def __init__(self):
        self.report = []

    def add_item(self, item):
        """
        Add a validation finding to the final report
        :param item: The report item to add as a validation finding
        """
        finding = {
            'rule': '{} - {}'.format(item.header, item.directive) if item.directive else item.header,
            'message': item.error_type.value.format('Directive' if item.directive else 'Header'),
            'severity': item.severity
        }

        if item.value:
            finding['value'] = item.value
        if item.expected:
            finding['expected'] = item.expected
            if len(item.expected) > 1 and item.delimiter:
                finding['delimiter'] = item.delimiter
        if item.avoid:
            finding['avoid'] = item.avoid
        if item.anomalies:
            finding['anomalies'] = item.anomalies
        self.report.append(finding)
