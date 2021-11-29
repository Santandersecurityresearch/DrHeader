import json
import logging
import os
import re

import unittest2
import yaml

from drheader import Drheader


class TestBase(unittest2.TestCase):

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
    def add_or_modify_header(header_name, update_value, headers=None):
        headers = TestBase.get_headers() if not headers else headers
        headers[header_name] = update_value
        return headers

    @staticmethod
    def delete_header(header_name, headers=None):
        headers = TestBase.get_headers() if not headers else headers
        if header_name in headers:
            headers.pop(header_name)
        return headers

    @staticmethod
    def modify_directive(header_name, update_value, pattern, headers=None):
        headers = TestBase.get_headers() if not headers else headers
        if header_name in headers:
            search_result = re.search(pattern, headers[header_name])
            if search_result:
                headers[header_name] = headers[header_name].replace(search_result.group(), update_value)
            else:
                headers[header_name] = headers[header_name] + '; ' + update_value
        else:
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


# start unittest2 to run these tests
if __name__ == "__main__":
    unittest2.main()
