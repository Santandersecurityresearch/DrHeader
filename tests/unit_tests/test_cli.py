import json
import os
import os.path
import tempfile
from unittest import mock, TestCase

import yaml
from click.testing import CliRunner
from xmlunittest import XmlTestMixin

from drheader import cli, cli_utils


# noinspection PyTypeChecker
class TestCli(TestCase):

    def setUp(self):
        with open(os.path.join(os.path.dirname(__file__), '../test_resources/report.json')) as report:
            self.report = json.load(report)
        with open(os.path.join(os.path.dirname(__file__), '../test_resources/default_rules.yml')) as rules:
            self.rules = yaml.safe_load(rules)

    @mock.patch('drheader.cli.Drheader')
    def test_compare_single__should_return_exit_code_0_on_clean_report(self, drheader_mock):
        file_path = os.path.join(os.path.dirname(__file__), '../test_resources/headers_ko.json')
        drheader_mock.return_value.analyze.return_value = []

        response = CliRunner().invoke(cli.main, ['compare', 'single', file_path])
        self.assertEqual(0, response.exit_code)

    @mock.patch('drheader.cli.Drheader')
    def test_compare_single__should_return_exit_code_70_on_rule_violation(self, drheader_mock):
        file_path = os.path.join(os.path.dirname(__file__), '../test_resources/headers_ko.json')
        drheader_mock.return_value.analyze.return_value = self.report

        response = CliRunner().invoke(cli.main, ['compare', 'single', file_path])
        self.assertEqual(70, response.exit_code)

    @mock.patch('drheader.cli.Drheader')
    def test_compare_single__should_disable_cross_origin_isolation_by_default(self, drheader_mock):
        file_path = os.path.join(os.path.dirname(__file__), '../test_resources/headers_ko.json')

        CliRunner().invoke(cli.main, ['compare', 'single', file_path])
        drheader_mock.return_value.analyze.assert_called_once_with(rules=mock.ANY, cross_origin_isolated=False)

    @mock.patch('drheader.cli.Drheader')
    def test_compare_single__should_enable_cross_origin_isolation(self, drheader_mock):
        file_path = os.path.join(os.path.dirname(__file__), '../test_resources/headers_ko.json')

        CliRunner().invoke(cli.main, ['compare', 'single', '--cross-origin-isolated', file_path])
        drheader_mock.return_value.analyze.assert_called_once_with(rules=mock.ANY, cross_origin_isolated=True)

    @mock.patch('drheader.cli.Drheader')
    def test_compare_single__should_output_json(self, drheader_mock):
        file_path = os.path.join(os.path.dirname(__file__), '../test_resources/headers_ko.json')
        drheader_mock.return_value.analyze.return_value = self.report

        response = CliRunner().invoke(cli.main, ['compare', 'single', '--output', 'json', file_path])
        self.assertEqual(self.report, json.loads(response.output))

    @mock.patch('drheader.cli.Drheader')
    def test_compare_bulk__should_return_exit_code_0_on_clean_report(self, drheader_mock):
        file_path = os.path.join(os.path.dirname(__file__), '../test_resources/headers_bulk_ko.json')
        drheader_mock.return_value.analyze.return_value = []

        response = CliRunner().invoke(cli.main, ['compare', 'bulk', file_path])
        self.assertEqual(0, response.exit_code)

    @mock.patch('drheader.cli.Drheader')
    def test_compare_bulk__should_return_exit_code_70_on_rule_violation(self, drheader_mock):
        file_path = os.path.join(os.path.dirname(__file__), '../test_resources/headers_bulk_ko.json')
        drheader_mock.return_value.analyze.return_value = self.report

        response = CliRunner().invoke(cli.main, ['compare', 'bulk', file_path])
        self.assertEqual(70, response.exit_code)

    @mock.patch('drheader.cli.Drheader')
    def test_compare_bulk__should_output_json(self, drheader_mock):
        file_path = os.path.join(os.path.dirname(__file__), '../test_resources/headers_bulk_ko.json')
        drheader_mock.return_value.analyze.return_value = self.report

        response = CliRunner().invoke(cli.main, ['compare', 'bulk', '--output', 'json', file_path])
        self.assertEqual(self.report, json.loads(response.output)[0]['report'])

    @mock.patch('drheader.cli.Drheader')
    def test_scan_single__should_return_exit_code_0_on_clean_report(self, drheader_mock):
        drheader_mock.return_value.analyze.return_value = []

        response = CliRunner().invoke(cli.main, ['scan', 'single', 'https://example.com'])
        self.assertEqual(0, response.exit_code)

    @mock.patch('drheader.cli.Drheader')
    def test_scan_single__should_return_exit_code_70_on_rule_violation(self, drheader_mock):
        drheader_mock.return_value.analyze.return_value = self.report

        response = CliRunner().invoke(cli.main, ['scan', 'single', 'https://example.com'])
        self.assertEqual(70, response.exit_code)

    @mock.patch('drheader.cli.Drheader')
    def test_scan_single__should_return_error_on_invalid_target_url(self, drheader_mock):
        response = CliRunner().invoke(cli.main, ['scan', 'single', 'https://example'])

        self.assertIn("'https://example' is not a valid URL", response.output)
        drheader_mock.assert_not_called()

    @mock.patch('drheader.cli.Drheader')
    def test_scan_single__should_disable_cross_origin_isolation_by_default(self, drheader_mock):
        CliRunner().invoke(cli.main, ['scan', 'single', 'https://example.com'])
        drheader_mock.return_value.analyze.assert_called_once_with(rules=mock.ANY, cross_origin_isolated=False)

    @mock.patch('drheader.cli.Drheader')
    def test_scan_single__should_enable_cross_origin_isolation(self, drheader_mock):
        CliRunner().invoke(cli.main, ['scan', 'single', '--cross-origin-isolated', 'https://example.com'])
        drheader_mock.return_value.analyze.assert_called_once_with(rules=mock.ANY, cross_origin_isolated=True)

    @mock.patch('drheader.cli.Drheader')
    def test_scan_single__should_output_json(self, drheader_mock):
        drheader_mock.return_value.analyze.return_value = self.report

        response = CliRunner().invoke(cli.main, ['scan', 'single', '--output', 'json', 'https://example.com'])
        self.assertEqual(self.report, json.loads(response.output))

    @mock.patch('drheader.cli.Drheader')
    def test_scan_bulk__should_return_exit_code_0_on_clean_report(self, drheader_mock):
        drheader_mock.return_value.analyze.return_value = []

        with tempfile.NamedTemporaryFile() as tmp:
            tmp.write(b'[{"url": "https://example1.com"}, {"url": "https://example2.com"}]')
            tmp.seek(0)
            response = CliRunner().invoke(cli.main, ['scan', 'bulk', tmp.name])

        self.assertEqual(0, response.exit_code)

    @mock.patch('drheader.cli.Drheader')
    def test_scan_bulk__should_return_exit_code_70_on_rule_violation(self, drheader_mock):
        drheader_mock.return_value.analyze.return_value = self.report

        with tempfile.NamedTemporaryFile() as tmp:
            tmp.write(b'[{"url": "https://example1.com"}, {"url": "https://example2.com"}]')
            tmp.seek(0)
            response = CliRunner().invoke(cli.main, ['scan', 'bulk', tmp.name])

        self.assertEqual(70, response.exit_code)

    @mock.patch('drheader.cli.Drheader')
    def test_scan_bulk__should_handle_json_file_type(self, drheader_mock):
        drheader_mock.return_value.analyze.return_value = self.report

        with tempfile.NamedTemporaryFile() as tmp:
            tmp.write(b'[{"url": "https://example1.com"}, {"url": "https://example2.com"}]')
            tmp.seek(0)
            CliRunner().invoke(cli.main, ['scan', 'bulk', '-ff', 'json', tmp.name])

        self.assertEqual(drheader_mock.call_args_list, [
            mock.call(url='https://example1.com', params=mock.ANY, verify=mock.ANY),
            mock.call(url='https://example2.com', params=mock.ANY, verify=mock.ANY)
        ])

    @mock.patch('drheader.cli.Drheader')
    def test_scan_bulk__should_handle_txt_file_type(self, drheader_mock):
        drheader_mock.return_value.analyze.return_value = self.report

        with tempfile.NamedTemporaryFile() as tmp:
            tmp.write(b'https://example1.com\nhttps://example2.com')
            tmp.seek(0)
            CliRunner().invoke(cli.main, ['scan', 'bulk', '-ff', 'txt', tmp.name])

        self.assertEqual(drheader_mock.call_args_list, [
            mock.call(url='https://example1.com', params=mock.ANY, verify=mock.ANY),
            mock.call(url='https://example2.com', params=mock.ANY, verify=mock.ANY)
        ])

    @mock.patch('drheader.cli.Drheader')
    def test_scan_bulk__should_output_json(self, drheader_mock):
        drheader_mock.return_value.analyze.return_value = self.report

        with tempfile.NamedTemporaryFile() as tmp:
            tmp.write(b'[{"url": "https://example1.com"}, {"url": "https://example2.com"}]')
            tmp.seek(0)
            response = CliRunner().invoke(cli.main, ['scan', 'bulk', '--output', 'json', tmp.name])

        self.assertEqual(self.report, json.loads(response.output)[0]['report'])


class TestUtils(TestCase, XmlTestMixin):

    def setUp(self):
        with open(os.path.join(os.path.dirname(__file__), '../test_resources/report.json')) as report:
            self.report = json.load(report)
        with open(os.path.join(os.path.dirname(__file__), '../test_resources/default_rules.yml')) as rules:
            self.rules = yaml.safe_load(rules)

        cli_utils.file_junit_report(self.rules, self.report)
        with open('reports/junit.xml') as junit_report:
            self.junit_xml = junit_report.read()

    def test_get_rules__should_return_default_rules_when_no_rules_provided(self):
        rules = cli_utils.get_rules()
        self.assertEqual(self.rules, rules)

    def test_file_junit_report__should_generate_xml_report(self):
        self.assertXmlDocument(self.junit_xml)

    def test_file_junit_report__should_create_test_case_for_all_rules(self):
        assert len(self.rules) > 0

        cli_utils.file_junit_report(self.rules, [])
        with open('reports/junit.xml') as junit_report:
            junit_xml = junit_report.read()

        xml_tree = self.assertXmlDocument(junit_xml)
        self.assertEqual(len(self.rules['Headers']), xml_tree.xpath('count(./testsuite/testcase)'))

    def test_file_junit_report__should_create_test_failure_for_all_report_items(self):
        assert len(self.report) > 0

        xml_tree = self.assertXmlDocument(self.junit_xml)
        self.assertXmlHasAttribute(xml_tree, 'failures', expected_value=str(len(self.report)))

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
