import json
import logging
import os
import re

import yaml
from unittest2 import TestCase

from drheader import Drheader


class TestBase(TestCase):

    def setUp(self):
        self.logger = logging.Logger

    def tearDown(self):
        with open(os.path.join(os.path.dirname(__file__), '../test_resources/default_rules.yml'), 'w') as test_rules_file,\
             open(os.path.join(os.path.dirname(__file__), '../../drheader/rules.yml')) as default_rules_file:
            default_rules = yaml.safe_load(default_rules_file.read())
            yaml.dump(default_rules, test_rules_file, sort_keys=False)

    def process_test(self, url=None, method="GET", headers=None, status_code=None):
        with open(os.path.join(os.path.dirname(__file__), '../test_resources/default_rules.yml'), 'r') as test_rules_file:
            rules = yaml.safe_load(test_rules_file.read())['Headers']

        self.instance = Drheader(url=url, method=method, headers=headers, status_code=status_code)
        self.instance.analyze(rules=rules)

    @staticmethod
    def get_headers():
        with open(os.path.join(os.path.dirname(__file__), '../test_resources/headers_ok.json'), 'r') as headers_file:
            return json.loads(headers_file.read())

    @staticmethod
    def modify_header(header_name, update_value, pattern=None):
        headers = TestBase.get_headers()
        if header_name in headers and pattern and update_value is not None:
            search_result = re.search(pattern, headers[header_name])
            if search_result:
                matched_string = search_result.group()
                headers[header_name] = headers[header_name].replace(matched_string, update_value)
            else:
                headers[header_name] = headers[header_name] + '; ' + update_value
        elif header_name in headers and update_value is None:
            headers.pop(header_name)
        elif update_value:
            headers[header_name] = update_value
        return headers

    @staticmethod
    def build_error_message(report, expected_report=None, rule=None, append_text=None):
        if expected_report is None:
            expected_report = []
        elif type(expected_report) is dict:
            expected_report = expected_report.items()

        unexpected_items = []
        for item in report:
            if rule and item['rule'] == rule and item not in expected_report:
                unexpected_items.append(item)
            elif not rule and item not in expected_report:
                unexpected_items.append(item)

        missing_items = []
        for item in expected_report:
            if item not in report:
                missing_items.append(item)

        error_message = "\n"
        if len(unexpected_items) > 0:
            error_message += "\nThe following items were found but were not expected in the report: \n"
            error_message += json.dumps(unexpected_items, indent=2)
        if len(missing_items) > 0:
            error_message += "\nThe following items were not found but were expected in the report: \n"
            error_message += json.dumps(missing_items, indent=2)
        if append_text:
            error_message = '%s\n\n%s' % (error_message, append_text)
        return error_message
