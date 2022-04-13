"""Primary module for report generation and storage."""
import enum
from typing import NamedTuple


class ErrorType(enum.Enum):
    AVOID = 'Must-Avoid directive included'
    CONTAIN = 'Must-Contain directive missed. All of the expected items were expected'
    CONTAIN_ONE = 'Must-Contain-One directive missed. At least one of the expected items was expected'
    DISALLOWED = '{} should not be returned'
    REQUIRED = '{} not included in response'
    VALUE = 'Value does not match security policy. All of the expected items were expected'
    VALUE_ANY = 'Value does not match security policy. At least one of the expected items was expected'
    VALUE_ONE = 'Value does not match security policy. Exactly one of the expected items was expected'


class ReportItem(NamedTuple):
    severity: str
    error_type: ErrorType
    header: str
    directive: str = None
    cookie: str = None
    value: str = None
    avoid: list = None
    expected: list = None
    anomalies: list = None
    delimiter: str = None


class Reporter:
    """Class to generate and store reports from a scan.

    Attributes:
        report (list): The report detailing validation failures encountered during a scan.
    """

    def __init__(self):
        """Initialises a Reporter instance with an empty report."""
        self.report = []

    def add_item(self, item):
        """Adds a validation failure to the report.

        Args:
            item (ReportItem): The validation failure to be added.
        """
        finding = {}
        if item.directive:
            finding['rule'] = f'{item.header} - {item.directive}'
            finding['message'] = item.error_type.value.format('Directive')
        elif item.cookie:
            finding['rule'] = f'{item.header} - {item.cookie}'
            finding['message'] = item.error_type.value.format('Cookie')
        else:
            finding['rule'] = item.header
            finding['message'] = item.error_type.value.format('Header')

        finding['severity'] = item.severity

        if item.value:
            finding['value'] = item.value
        if item.expected:
            finding['expected'] = item.expected
            if len(item.expected) > 1 and item.delimiter:
                finding['delimiter'] = item.delimiter
        elif item.avoid:
            finding['avoid'] = item.avoid
        if item.anomalies:
            finding['anomalies'] = item.anomalies
        self.report.append(finding)
