#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Tests for `cli_utils.py` file."""

import os
import yaml
import json
import unittest2
import xmlunittest

from drheader.cli_utils import file_junit_report


class TestCliUtilsFunctions(unittest2.TestCase, xmlunittest.XmlTestMixin):
    def setUp(self):
        with open(os.path.join(os.path.dirname(__file__), 'testfiles/default_rules.yml'), 'r') as f:
            self.rules = yaml.safe_load(f.read())['Headers']
            f.close()

        with open(os.path.join(os.path.dirname(__file__), 'testfiles/example_report.json'), 'r') as f:
            self.report = json.loads(f.read())
            f.close()

        file_junit_report(self.rules, self.report)

        with open('reports/junit.xml', 'r') as f:
            self.xml = f.read()
            f.close()

    def test_file_junit_report_writes_default_file(self):
        self.assertXmlDocument(self.xml)

    def test_file_junit_report_contains_test_suites_node(self):
        root = self.assertXmlDocument(self.xml)
        self.assertXmlNode(root, tag='testsuites')

    def test_file_junit_report_contains_ten_failures_and_seventeen_cases(self):
        root = self.assertXmlDocument(self.xml)
        self.assertXmlHasAttribute(root, 'failures', expected_values=('10'))
        self.assertXmlHasAttribute(root, 'tests', expected_values=('17'))

    def test_file_junit_report_contains_only_one_testsuite(self):
        root = self.assertXmlDocument(self.xml)
        self.assertXpathsOnlyOne(root, ('./testsuite', './testsuite[@name="DrHeader"]'))

    def test_file_junit_report_contains_all_header_as_testcases(self):
        root = self.assertXmlDocument(self.xml)
        for item in self.rules:
            self.assertXpathsExist(root, ('./testsuite/testcase', './testsuite/testcase[contains(@name,'+item+')]'))

    def test_file_junit_report_contains_seventeen_testcases(self):
        root = self.assertXmlDocument(self.xml)
        self.assertEqual(root.xpath('count(./testsuite/testcase)'), 17)


# start unittest2 to run these tests
if __name__ == "__main__":
    unittest2.main()
