import json
import os
import os.path
import tempfile
from unittest import mock

import unittest2
import xmlunittest
import yaml
from click import ClickException
from click.testing import CliRunner

from drheader import cli
from drheader.cli_utils import file_junit_report


class TestCli(unittest2.TestCase):

    def setUp(self):
        with open(os.path.join(os.path.dirname(__file__), '../test_resources/example_report.json')) as report_file:
            self.mock_report = json.load(report_file)
        with open(os.path.join(os.path.dirname(__file__), '../test_resources/default_rules.yml')) as rules_file:
            self.mock_rules = yaml.safe_load(rules_file)

    @mock.patch('drheader.cli.load_rules')
    @mock.patch('drheader.cli.Drheader')
    def test_compare_should_analyse_headers(self, drheader_mock, load_rules_mock):
        drheader_instance = drheader_mock.return_value
        drheader_instance.reporter.report = self.mock_report
        load_rules_mock.return_value = self.mock_rules

        with tempfile.NamedTemporaryFile() as tmp:
            tmp.write(b'[{"url": "https://test1.com", "headers": {"X-XSS-Protection": "1; mode=block"}},'
                      b'{"url": "https://test2.com", "headers": {"X-Frame-Options": "DENY"}}]')
            tmp.seek(0)
            runner = CliRunner()
            runner.invoke(cli.main, ['compare', tmp.name])

        self.assertEqual(drheader_mock.call_args_list, [
            mock.call(url='https://test1.com', headers={'X-XSS-Protection': '1; mode=block'}),
            mock.call(url='https://test2.com', headers={'X-Frame-Options': 'DENY'})
        ])

    @mock.patch('drheader.cli.load_rules')
    @mock.patch('drheader.cli.Drheader')
    def test_compare_invalid_format_should_raise_exception_and_exit(self, drheader_mock, load_rules_mock):
        drheader_instance = drheader_mock.return_value
        drheader_instance.reporter.report = self.mock_report
        load_rules_mock.return_value = self.mock_rules

        with tempfile.NamedTemporaryFile() as tmp:
            tmp.write(b'[{"url": "https://test1.com", "http_headers": {"X-XSS-Protection": "1; mode=block"}}]')
            tmp.seek(0)
            runner = CliRunner()
            result = runner.invoke(cli.main, ['compare', tmp.name])

        self.assertEqual(ClickException.exit_code, result.exit_code)
        self.assertIn("Error: 'headers' is a required property", result.output)

    @mock.patch('drheader.cli.load_rules')
    @mock.patch('drheader.cli.Drheader')
    def test_scan_single_should_analyse_target_url(self, drheader_mock, load_rules_mock):
        drheader_instance = drheader_mock.return_value
        drheader_instance.reporter.report = self.mock_report
        load_rules_mock.return_value = self.mock_rules

        runner = CliRunner()
        runner.invoke(cli.main, ['scan', 'single', 'https://www.google.com'])

        drheader_mock.assert_called_once_with(url='https://www.google.com', verify=mock.ANY)

    @mock.patch('drheader.cli.load_rules')
    @mock.patch('drheader.cli.Drheader')
    def test_scan_single_with_json_flag_should_output_json(self, drheader_mock, load_rules_mock):
        drheader_instance = drheader_mock.return_value
        drheader_instance.reporter.report = self.mock_report
        load_rules_mock.return_value = self.mock_rules

        runner = CliRunner()
        result = runner.invoke(cli.main, ['scan', 'single', 'https://www.google.com', '--json'])

        with open(os.path.join(os.path.dirname(__file__), '../test_resources/example_report.json')) as report_file:
            self.assertEqual(json.load(report_file), json.loads(result.output))

    @mock.patch('drheader.cli.file_junit_report')
    @mock.patch('drheader.cli.load_rules')
    @mock.patch('drheader.cli.Drheader')
    def test_scan_single_with_junit_flag_should_write_junit_report(self, drheader_mock, load_rules_mock, junit_mock):
        drheader_instance = drheader_mock.return_value
        drheader_instance.reporter.report = self.mock_report
        load_rules_mock.return_value = self.mock_rules

        runner = CliRunner()
        runner.invoke(cli.main, ['scan', 'single', 'https://www.google.com', '--junit'])

        junit_mock.assert_called_once_with(self.mock_rules, self.mock_report)

    @mock.patch('drheader.cli.load_rules')
    @mock.patch('drheader.cli.Drheader')
    def test_scan_bulk_should_read_json_file(self, drheader_mock, load_rules_mock):
        drheader_instance = drheader_mock.return_value
        drheader_instance.reporter.report = self.mock_report
        load_rules_mock.return_value = self.mock_rules

        with tempfile.NamedTemporaryFile() as tmp:
            tmp.write(b'[{"url": "https://test1.com"}, {"url": "https://test2.com"}, {"url": "https://test3.com"}]')
            tmp.seek(0)
            runner = CliRunner()
            runner.invoke(cli.main, ['scan', 'bulk', tmp.name])

        self.assertEqual(drheader_mock.call_args_list, [
            mock.call(url='https://test1.com', params=mock.ANY, verify=mock.ANY),
            mock.call(url='https://test2.com', params=mock.ANY, verify=mock.ANY),
            mock.call(url='https://test3.com', params=mock.ANY, verify=mock.ANY),
        ])

    @mock.patch('drheader.cli.load_rules')
    @mock.patch('drheader.cli.Drheader')
    def test_scan_bulk_should_read_txt_file(self, drheader_mock, load_rules_mock):
        drheader_instance = drheader_mock.return_value
        drheader_instance.reporter.report = self.mock_report
        load_rules_mock.return_value = self.mock_rules

        with tempfile.NamedTemporaryFile() as tmp:
            tmp.write(b'https://test1.com\nhttps://test2.com\nhttps://test3.com')
            tmp.seek(0)
            runner = CliRunner()
            runner.invoke(cli.main, ['scan', 'bulk', '-ff', 'txt', tmp.name])

        self.assertEqual(drheader_mock.call_args_list, [
            mock.call(url='https://test1.com', params=mock.ANY, verify=mock.ANY),
            mock.call(url='https://test2.com', params=mock.ANY, verify=mock.ANY),
            mock.call(url='https://test3.com', params=mock.ANY, verify=mock.ANY),
        ])

    @mock.patch('drheader.cli.load_rules')
    @mock.patch('drheader.cli.Drheader')
    def test_scan_bulk_invalid_format_should_raise_exception_and_exit(self, drheader_mock, load_rules_mock):
        drheader_instance = drheader_mock.return_value
        drheader_instance.reporter.report = self.mock_report
        load_rules_mock.return_value = self.mock_rules

        with tempfile.NamedTemporaryFile() as tmp:
            tmp.write(b'[{"address": "https://test1.com"}, {"url": "https://test2.com"}]')
            tmp.seek(0)
            runner = CliRunner()
            result = runner.invoke(cli.main, ['scan', 'bulk', tmp.name])

        self.assertEqual(ClickException.exit_code, result.exit_code)
        self.assertIn("Error: 'url' is a required property", result.output)


class TestCliUtils(unittest2.TestCase, xmlunittest.XmlTestMixin):

    def setUp(self):
        with open(os.path.join(os.path.dirname(__file__), '../test_resources/default_rules.yml')) as f:
            self.rules = yaml.safe_load(f.read())['Headers']
        with open(os.path.join(os.path.dirname(__file__), '../test_resources/example_report.json')) as f:
            self.report = json.loads(f.read())

        file_junit_report(self.rules, self.report)
        with open('reports/junit.xml') as f:
            self.xml = f.read()

    def test_file_junit_report_writes_default_file(self):
        self.assertXmlDocument(self.xml)

    def test_file_junit_report_contains_test_suites_node(self):
        root = self.assertXmlDocument(self.xml)
        self.assertXmlNode(root, tag='testsuites')

    def test_file_junit_report_contains_ten_failures_and_seventeen_cases(self):
        root = self.assertXmlDocument(self.xml)
        self.assertXmlHasAttribute(root, 'failures', expected_values='10')
        self.assertXmlHasAttribute(root, 'tests', expected_values='19')

    def test_file_junit_report_contains_only_one_testsuite(self):
        root = self.assertXmlDocument(self.xml)
        self.assertXpathsOnlyOne(root, ('./testsuite', './testsuite[@name="DrHeader"]'))

    def test_file_junit_report_contains_all_header_as_testcases(self):
        root = self.assertXmlDocument(self.xml)
        for item in self.rules:
            self.assertXpathsExist(root, ('./testsuite/testcase', './testsuite/testcase[contains(@name,'+item+')]'))

    def test_file_junit_report_contains_seventeen_testcases(self):
        root = self.assertXmlDocument(self.xml)
        self.assertEqual(root.xpath('count(./testsuite/testcase)'), 19)


# start unittest2 to run these tests
if __name__ == "__main__":
    unittest2.main()
