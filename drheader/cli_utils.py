# -*- coding: utf-8 -*-
"""Utility functions for cli module."""

import json
import os

import click
from junit_xml import TestSuite, TestCase


def echo_bulk_report(audit, json_output=False):
    """Prints a report from a bulk scan.

    Args:
        audit (list): The report generated from the scan.
        json_output (bool): (optional) A flag to format the output as JSON. Default is false.
    """
    if json_output:
        click.echo(json.dumps(audit))
    else:
        for i in audit:
            issues_header = '{url}: {issues} issues'.format(issues=len(i['report']), url=i['url'])
            click.echo()
            click.echo(issues_header)
            click.echo('=' * len(issues_header))
            for _ in i['report']:
                for v, k in _.items():
                    click.echo('{}: {}'.format(v, k))
                click.echo('----')


def file_junit_report(rules, report):
    """Generates a JUnit XML report from a scan result.

    Args:
        rules (dict): The rules used to perform the scan.
        report (list): The report generated from the scan.
    """
    test_cases = []

    for header in rules:
        tc = []
        for item in report:
            if item.get('rule') == header:
                violation = item.copy()
                violation.pop('rule')
                message = violation.pop('message')
                tc = TestCase(name=header + ' :: ' + message)
                tc.add_failure_info(message, violation)
                test_cases.append(tc)
        if not tc:
            tc = TestCase(name=header)
            test_cases.append(tc)

    os.makedirs('reports', exist_ok=True)
    with open('reports/junit.xml', 'w') as f:
        TestSuite.to_file(f, [TestSuite(name='DrHeader', test_cases=test_cases)], prettyprint=False)
        f.close()
