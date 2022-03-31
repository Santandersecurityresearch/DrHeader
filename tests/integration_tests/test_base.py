import json
import os

import unittest2
import yaml

from drheader import Drheader


class TestBase(unittest2.TestCase):

    def tearDown(self):
        self._reset_default_rules()

    @staticmethod
    def process_test(headers=None, url=None, cross_origin_isolated=False):
        with open(os.path.join(os.path.dirname(__file__), '../test_resources/default_rules.yml')) as rules:
            rules = yaml.safe_load(rules.read())['Headers']

        drheader = Drheader(headers=headers, url=url)
        return drheader.analyze(rules=rules, cross_origin_isolated=cross_origin_isolated)

    @staticmethod
    def get_headers():
        with open(os.path.join(os.path.dirname(__file__), '../test_resources/headers_ok.json')) as headers:
            return json.load(headers)

    @staticmethod
    def add_or_modify_header(header_name, update_value):
        headers = TestBase.get_headers()
        headers[header_name] = update_value
        return headers

    @staticmethod
    def delete_headers(*header_names):
        headers = TestBase.get_headers()
        for header in header_names:
            headers.pop(header, None)
        return headers

    @staticmethod
    def build_error_message(report, expected=None, rule=None):
        unexpected_items = []
        for item in report:
            if item != expected:
                if rule and item['rule'].startswith(rule):
                    unexpected_items.append(item)
                elif not rule:
                    unexpected_items.append(item)

        error_message = '\n'
        if len(unexpected_items) > 0:
            error_message += '\nThe following items were found but were not expected in the report:\n'
            error_message += json.dumps(unexpected_items, indent=2)
        if expected and expected not in report:
            error_message += '\n\nThe following was not found but was expected in the report:\n'
            error_message += json.dumps(expected, indent=2)
        return error_message

    @staticmethod
    def _reset_default_rules():
        with open(os.path.join(os.path.dirname(__file__), '../../drheader/rules.yml')) as rules, \
             open(os.path.join(os.path.dirname(__file__), '../test_resources/default_rules.yml'), 'w') as default_rules:
            rules = yaml.safe_load(rules.read())
            yaml.dump(rules, default_rules, indent=2, sort_keys=False)
