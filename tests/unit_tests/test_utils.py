#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Tests for `utils.py` file."""

import os
import yaml
import unittest2
import responses

from drheader.utils import load_rules, get_rules_from_uri


class TestUtilsFunctions(unittest2.TestCase):

    def setUp(self):
        with open(os.path.join(os.path.dirname(__file__), '../test_resources/default_rules.yml'), 'r') as f:
            self.default_rules = yaml.safe_load(f.read())
            f.close()
        with open(os.path.join(os.path.dirname(__file__), '../test_resources/custom_rules.yml'), 'r') as f:
            self.custom_rules = yaml.safe_load(f.read())
            f.close()
        with open(os.path.join(os.path.dirname(__file__), '../test_resources/custom_rules_merged.yml'), 'r') as f:
            self.custom_rules_merged = yaml.safe_load(f.read())
            f.close()

    def test_load_rules_should_load_default_rules_when_no_rules_file_is_provided(self):
        rules = load_rules()
        self.assertEqual(rules, self.default_rules['Headers'])

    def test_load_rules_should_load_custom_rules_when_a_rules_file_is_provided(self):
        with open(os.path.join(os.path.dirname(__file__), '../test_resources/custom_rules.yml'), 'r') as f:
            rules = load_rules(f)
            f.close()

        self.assertEqual(rules, self.custom_rules['Headers'])

    def test_load_rules_should_merge_custom_rules_with_default_rules_when_merge_flag_is_true(self):
        with open(os.path.join(os.path.dirname(__file__), '../test_resources/custom_rules.yml'), 'r') as f:
            rules = load_rules(f, True)
            f.close()

        self.assertEqual(rules, self.custom_rules_merged['Headers'])

    @responses.activate
    def test_get_rules_from_uri_should_return_rules_from_a_valid_uri(self):
        uri = 'http://localhost:8080/custom.yml'
        responses.add(responses.GET, uri, json=self.custom_rules, status=200)

        rules_file = get_rules_from_uri(uri)
        rules = yaml.safe_load(rules_file.read())
        self.assertEqual(rules, self.custom_rules)

    @responses.activate
    def test_get_rules_from_uri_should_raise_an_error_when_no_content_is_found(self):
        uri = 'http://mydomain.com/custom.yml'
        responses.add(responses.GET, uri, status=404)

        with self.assertRaises(Exception) as e:
            get_rules_from_uri(uri)
        self.assertEqual('No content retrieved from {}'.format(uri), str(e.exception))


# start unittest2 to run these tests
if __name__ == "__main__":
    unittest2.main()
