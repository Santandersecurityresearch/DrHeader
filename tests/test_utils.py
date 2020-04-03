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
        with open(os.path.join(os.path.dirname(__file__), 'testfiles/default_rules.yml'), 'r') as f:
            self.default_rules = yaml.safe_load(f.read())
            f.close()
        with open(os.path.join(os.path.dirname(__file__), 'testfiles/custom_rules.yml'), 'r') as f:
            self.custom_rules = yaml.safe_load(f.read())
            f.close()
        with open(os.path.join(os.path.dirname(__file__), 'testfiles/custom_rules_merged.yml'), 'r') as f:
            self.custom_rules_merged = yaml.safe_load(f.read())
            f.close()

    def test_load_rules_default(self):
        rules = load_rules()
        self.assertEqual(rules, self.default_rules['Headers'])

    def test_load_rules_custom(self):
        with open(os.path.join(os.path.dirname(__file__), 'testfiles/custom_rules.yml'), 'r') as f:
            rules = load_rules(f)
            f.close()
        self.assertNotEqual(rules, self.default_rules['Headers'])
        self.assertEqual(rules, self.custom_rules['Headers'])

    def test_load_rules_custom_and_merge(self):
        with open(os.path.join(os.path.dirname(__file__), 'testfiles/custom_rules.yml'), 'r') as f:
            rules = load_rules(f, True)
            f.close()
        self.assertNotEqual(rules, self.default_rules['Headers'])
        self.assertNotEqual(rules, self.custom_rules['Headers'])
        self.assertEqual(rules, self.custom_rules_merged['Headers'])

    def test_load_rules_bad_parameter(self):
        with self.assertRaises(AttributeError):
            load_rules(2)

    @responses.activate
    def test_get_rules_from_uri_wrong_URI(self):
        responses.add(responses.GET, 'http://mydomain.com/custom.yml', status=404)
        with self.assertRaises(Exception):
            get_rules_from_uri("http://mydomain.com/custom.yml")

    @responses.activate
    def test_get_rules_from_uri_good_URI(self):
        responses.add(responses.GET, 'http://localhost:8080/custom.yml', json=self.custom_rules, status=200)
        file = get_rules_from_uri("http://localhost:8080/custom.yml")
        content = yaml.safe_load(file.read())
        self.assertEqual(content, self.custom_rules)


# start unittest2 to run these tests
if __name__ == "__main__":
    unittest2.main()
