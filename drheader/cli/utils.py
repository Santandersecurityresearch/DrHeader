"""Utility functions for cli module."""

import os

import junit_xml
import tabulate
from junit_xml import TestSuite, TestCase

from drheader import utils


def get_rules(rules_file=None, rules_uri=None, merge_default=False):
    if rules_file or rules_uri:
        return utils.load_rules(rules_file=rules_file, rules_uri=rules_uri, merge_default=merge_default)
    else:
        return utils.default_rules()


def tabulate_report(report):
    rows = []
    final_string = ''

    for validation_error in report:
        values = [[k, v] for k, v in validation_error.items()]
        rows.append(values)
    for validation_error in rows:
        final_string += '----\n'
        final_string += tabulate.tabulate(validation_error, tablefmt='presto') + '\n'

    return final_string


def file_junit_report(rules, report):
    """Generates a JUnit XML report from a scan result.

    Args:
        rules (dict): The rules used to perform the scan.
        report (list): The report generated from the scan.
    """
    test_cases = []

    for header in rules:
        test_case = None
        for validation_error in report:
            if (title := validation_error.get('rule')).startswith(header):
                validation_error = {k: v for k, v in validation_error.items() if k != 'rule'}
                test_case = TestCase(name=title)
                test_case.add_failure_info(message=validation_error.pop('message'), output=validation_error)
                test_cases.append(test_case)
        if not test_case:
            test_case = TestCase(name=header)
            test_cases.append(test_case)

    os.makedirs('reports', exist_ok=True)
    test_suite = TestSuite(name='drHEADer', test_cases=test_cases)

    with open('reports/junit.xml', 'w') as junit_report:
        junit_xml.to_xml_report_file(junit_report, [test_suite])
        junit_report.close()
