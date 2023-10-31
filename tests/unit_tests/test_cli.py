import json
import os
import os.path
from unittest import mock, TestCase

import yaml
from click.testing import CliRunner
from xmlunittest import XmlTestMixin

from drheader.cli import cli, utils

_RESOURCES_DIR = os.path.join(os.path.dirname(__file__), '../test_resources')


# noinspection PyTypeChecker
class TestCli(TestCase):

    def setUp(self):
        with open(os.path.join(_RESOURCES_DIR, 'report.json')) as report:
            self.report = json.load(report)

    @mock.patch('drheader.cli.cli.Drheader')
    def test_compare_single__should_return_exit_code_0_on_clean_report(self, drheader_mock):
        drheader_mock.return_value.analyze.return_value = []

        file = os.path.join(_RESOURCES_DIR, 'headers_ok.json')
        response = CliRunner().invoke(cli.main, ['compare', 'single', file])

        assert response.exit_code == 0

    @mock.patch('drheader.cli.cli.Drheader')
    def test_compare_single__should_return_exit_code_70_on_rule_violation(self, drheader_mock):
        drheader_mock.return_value.analyze.return_value = self.report

        file = os.path.join(_RESOURCES_DIR, 'headers_ko.json')
        response = CliRunner().invoke(cli.main, ['compare', 'single', file])

        assert response.exit_code == 70

    @mock.patch('drheader.cli.cli.Drheader')
    def test_compare_single__should_enable_cross_origin_isolation(self, drheader_mock):
        file = os.path.join(_RESOURCES_DIR, 'headers_ko.json')
        CliRunner().invoke(cli.main, ['compare', 'single', '--cross-origin-isolated', file])

        drheader_mock.return_value.analyze.assert_called_once_with(rules=mock.ANY, cross_origin_isolated=True)

    @mock.patch('drheader.cli.cli.Drheader')
    def test_compare_single__should_output_json(self, drheader_mock):
        drheader_mock.return_value.analyze.return_value = self.report

        file = os.path.join(_RESOURCES_DIR, 'headers_ko.json')
        response = CliRunner().invoke(cli.main, ['compare', 'single', '--output', 'json', file])

        assert json.loads(response.output) == self.report

    @mock.patch('drheader.cli.cli.Drheader')
    def test_compare_bulk__should_return_exit_code_0_on_clean_report(self, drheader_mock):
        drheader_mock.return_value.analyze.return_value = []

        file = os.path.join(_RESOURCES_DIR, 'headers_bulk_ok.json')
        response = CliRunner().invoke(cli.main, ['compare', 'bulk', file])

        assert response.exit_code == 0

    @mock.patch('drheader.cli.cli.Drheader')
    def test_compare_bulk__should_return_exit_code_70_on_rule_violation(self, drheader_mock):
        drheader_mock.return_value.analyze.return_value = self.report

        file = os.path.join(_RESOURCES_DIR, 'headers_bulk_ko.json')
        response = CliRunner().invoke(cli.main, ['compare', 'bulk', file])

        assert response.exit_code == 70

    @mock.patch('drheader.cli.cli.Drheader')
    def test_compare_bulk__should_output_json(self, drheader_mock):
        drheader_mock.return_value.analyze.return_value = self.report

        file = os.path.join(_RESOURCES_DIR, 'headers_bulk_ko.json')
        response = CliRunner().invoke(cli.main, ['compare', 'bulk', '--output', 'json', file])

        assert json.loads(response.output)[0]['report'] == self.report

    @mock.patch('drheader.cli.cli.Drheader')
    def test_scan_single__should_return_exit_code_0_on_clean_report(self, drheader_mock):
        drheader_mock.return_value.analyze.return_value = []
        response = CliRunner().invoke(cli.main, ['scan', 'single', 'https://example.com'])

        assert response.exit_code == 0

    @mock.patch('drheader.cli.cli.Drheader')
    def test_scan_single__should_return_exit_code_70_on_rule_violation(self, drheader_mock):
        drheader_mock.return_value.analyze.return_value = self.report
        response = CliRunner().invoke(cli.main, ['scan', 'single', 'https://example.com'])

        assert response.exit_code == 70

    @mock.patch('drheader.cli.cli.Drheader')
    def test_scan_single__should_enable_cross_origin_isolation(self, drheader_mock):
        CliRunner().invoke(cli.main, ['scan', 'single', '--cross-origin-isolated', 'https://example.com'])

        drheader_mock.return_value.analyze.assert_called_once_with(rules=mock.ANY, cross_origin_isolated=True)

    @mock.patch('drheader.cli.cli.Drheader')
    def test_scan_single__should_output_json(self, drheader_mock):
        drheader_mock.return_value.analyze.return_value = self.report
        response = CliRunner().invoke(cli.main, ['scan', 'single', '--output', 'json', 'https://example.com'])

        assert json.loads(response.output) == self.report

    @mock.patch('drheader.cli.cli.Drheader')
    def test_scan_bulk__should_return_exit_code_0_on_clean_report(self, drheader_mock):
        drheader_mock.return_value.analyze.return_value = []

        file = os.path.join(_RESOURCES_DIR, 'bulk_scan.json')
        response = CliRunner().invoke(cli.main, ['scan', 'bulk', file])

        assert response.exit_code == 0

    @mock.patch('drheader.cli.cli.Drheader')
    def test_scan_bulk__should_return_exit_code_70_on_rule_violation(self, drheader_mock):
        drheader_mock.return_value.analyze.return_value = self.report

        file = os.path.join(_RESOURCES_DIR, 'bulk_scan.json')
        response = CliRunner().invoke(cli.main, ['scan', 'bulk', file])

        assert response.exit_code == 70

    @mock.patch('drheader.cli.cli.Drheader')
    def test_scan_bulk__should_handle_json_file_type(self, drheader_mock):
        drheader_mock.return_value.analyze.return_value = self.report

        file = os.path.join(_RESOURCES_DIR, 'bulk_scan.json')
        CliRunner().invoke(cli.main, ['scan', 'bulk', '-ff', 'json', file])

        assert drheader_mock.call_args_list == [
            mock.call(url='https://example.com'),
            mock.call(url='https://example.net'),
            mock.call(url='https://example.org')
        ]

    @mock.patch('drheader.cli.cli.Drheader')
    def test_scan_bulk__should_handle_txt_file_type(self, drheader_mock):
        drheader_mock.return_value.analyze.return_value = self.report

        file = os.path.join(_RESOURCES_DIR, 'bulk_scan.txt')
        CliRunner().invoke(cli.main, ['scan', 'bulk', '-ff', 'txt', file])

        assert drheader_mock.call_args_list == [
            mock.call(url='https://example.com'),
            mock.call(url='https://example.net'),
            mock.call(url='https://example.org')
        ]

    @mock.patch('drheader.cli.cli.Drheader')
    def test_scan_bulk__should_output_json(self, drheader_mock):
        drheader_mock.return_value.analyze.return_value = self.report

        file = os.path.join(_RESOURCES_DIR, 'bulk_scan.json')
        response = CliRunner().invoke(cli.main, ['scan', 'bulk', '--output', 'json', file])

        assert json.loads(response.output)[0]['report'] == self.report

    @mock.patch('drheader.cli.cli.Drheader')
    def test_scan_bulk__should_not_fail_on_error(self, drheader_mock):
        def raise_error(url):
            if url == 'https://example.net':
                raise ValueError('Error retrieving headers')
            else:
                return drheader_mock

        drheader_mock.analyze.return_value = self.report
        drheader_mock.side_effect = raise_error

        file = os.path.join(_RESOURCES_DIR, 'bulk_scan.json')
        response = CliRunner().invoke(cli.main, ['scan', 'bulk', '--output', 'json', file])

        assert json.loads(response.output)[1]['error'] == 'Error retrieving headers'


class TestUtils(TestCase, XmlTestMixin):

    def setUp(self):
        with open(os.path.join(_RESOURCES_DIR, 'report.json')) as report:
            self.report = json.load(report)
        with open(os.path.join(_RESOURCES_DIR, 'default_rules.yml')) as rules:
            self.rules = yaml.safe_load(rules)

        utils.file_junit_report(self.rules, self.report)
        with open('reports/junit.xml') as junit_report:
            self.junit_xml = junit_report.read()

    def test_get_rules__should_return_default_rules_when_no_rules_provided(self):
        rules = utils.get_rules()
        assert rules == self.rules

    def test_file_junit_report__should_create_test_case_for_header(self):
        assert any(item['rule'] == 'Cache-Control' for item in self.report)

        xml_tree = self.assertXmlDocument(self.junit_xml)
        self.assertXpathsExist(xml_tree, ['./testsuite/testcase[@name="Cache-Control"]'])

    def test_file_junit_report__should_create_test_case_for_directive(self):
        assert any(item['rule'] == 'Content-Security-Policy - default-src' for item in self.report)

        xml_tree = self.assertXmlDocument(self.junit_xml)
        self.assertXpathsExist(xml_tree, ['./testsuite/testcase[@name="Content-Security-Policy - default-src"]'])

    def test_file_junit_report__should_create_test_case_for_cookie(self):
        assert any(item['rule'] == 'Set-Cookie - session_id' for item in self.report)

        xml_tree = self.assertXmlDocument(self.junit_xml)
        self.assertXpathsExist(xml_tree, ['./testsuite/testcase[@name="Set-Cookie - session_id"]'])

    def test_file_junit_report__should_create_test_failure_for_each_report_item(self):
        assert len(self.report) > 0

        xml_tree = self.assertXmlDocument(self.junit_xml)
        self.assertXmlHasAttribute(xml_tree, 'failures', expected_value=str(len(self.report)))
