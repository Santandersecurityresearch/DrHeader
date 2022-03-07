from enum import Enum


class ErrorType(Enum):
    DISALLOWED = '{} should not be returned'
    AVOID = 'Must-Avoid directive included'
    CONTAIN = 'Must-Contain directive missed'
    CONTAIN_ONE = 'Must-Contain-One directive missed'
    REQUIRED = '{} not included in response'
    VALUE = 'Value does not match security policy'


class ReportItem:

    def __init__(self, severity, error_type, header, directive=None, value=None, avoid=None, expected=None,
                 expected_one=None, anomaly=None, delimiter=None):
        self.severity = severity
        self.error_type = error_type
        self.header = header
        self.directive = directive
        self.value = value
        self.avoid = avoid
        self.expected = expected
        self.expected_one = expected_one
        self.anomaly = anomaly
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
            'severity': item.severity,
        }
        if item.error_type in (ErrorType.DISALLOWED, ErrorType.REQUIRED):
            finding['message'] = item.error_type.value.format('Directive' if item.directive else 'Header')
        else:
            finding['message'] = item.error_type.value

        if item.value:
            finding['value'] = item.value
        if item.expected:
            finding['expected'] = item.expected
            if len(item.expected) > 1 and item.delimiter:
                finding['delimiter'] = item.delimiter
        elif item.expected_one:
            finding['expected-one'] = item.expected_one
        if item.avoid:
            finding['avoid'] = item.avoid
        if item.anomaly:
            finding['anomaly'] = item.anomaly
        self.report.append(finding)
