#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Tests for `utils.py` file."""

import os

import responses
import unittest2
import yaml

from drheader.utils import load_rules, get_rules_from_uri, parse_policy, KeyValueDirective


class TestUtilsFunctions(unittest2.TestCase):

    def setUp(self):
        with open(os.path.join(os.path.dirname(__file__), '../test_resources/default_rules.yml')) as f:
            self.default_rules = yaml.safe_load(f.read())
        with open(os.path.join(os.path.dirname(__file__), '../test_resources/custom_rules.yml')) as f:
            self.custom_rules = yaml.safe_load(f.read())
        with open(os.path.join(os.path.dirname(__file__), '../test_resources/custom_rules_merged.yml')) as f:
            self.custom_rules_merged = yaml.safe_load(f.read())

    def test_parse_policy__standalone_directive__ok(self):
        policy = 'session_id=74839222; Secure'
        directives_list = parse_policy(policy, ';', '=')

        self.assertIn('Secure', directives_list)

    def test_parse_policy__key_value_directive__ok(self):
        policy = 'session_id=74839222; Secure'
        directives_list = parse_policy(policy, ';', '=')

        expected = KeyValueDirective('session_id', ['74839222'], '74839222')
        self.assertIn(expected, directives_list)

    def test_parse_policy__repeated_delimiters__ok(self):
        policy = "default-src 'none';;  ;;   script-src   'self'   'unsafe-inline';;"
        directives_list = parse_policy(policy, ';', ' ', value_delimiter=' ')

        expected = KeyValueDirective('script-src', ["'self'", "'unsafe-inline'"], "  'self'   'unsafe-inline'")
        self.assertIn(expected, directives_list)

    def test_parse_policy__key_value_directive__should_extract_all_values(self):
        policy = "default-src 'none'; script-src https: 'unsafe-inline'"
        directives_list = parse_policy(policy, ';', ' ', value_delimiter=' ')

        expected = KeyValueDirective('script-src', ['https:', "'unsafe-inline'"], "https: 'unsafe-inline'")
        self.assertIn(expected, directives_list)

    def test_parse_policy__strip_items__should_strip_from_values(self):
        policy = "default-src 'none'; script-src 'self' 'unsafe-inline'"
        directives_list = parse_policy(policy, ';', ' ', value_delimiter=' ', strip_items='\'')

        expected = KeyValueDirective('script-src', ['self', 'unsafe-inline'], "'self' 'unsafe-inline'")
        self.assertIn(expected, directives_list)

    def test_parse_policy__keys_only__should_return_only_keys_and_standalone_directives(self):
        policy = "default-src 'none'; script-src https: 'unsafe-inline'; upgrade-insecure-requests"
        directives_list = parse_policy(policy, ';', ' ', value_delimiter=' ', keys_only=True)

        expected = ['default-src', 'script-src', 'upgrade-insecure-requests']
        self.assertCountEqual(expected, directives_list)

    def test_parse_policy__key_values_only__should_return_only_key_value_directives(self):
        policy = "default-src 'none'; script-src https: 'unsafe-inline'; upgrade-insecure-requests"
        directives_list = parse_policy(policy, ';', ' ', value_delimiter=' ', key_values_only=True)

        expected = [
            KeyValueDirective(key='default-src', value=["'none'"], raw_value="'none'"),
            KeyValueDirective(key='script-src', value=['https:', "'unsafe-inline'"], raw_value="https: 'unsafe-inline'")
        ]
        self.assertCountEqual(expected, directives_list)

    def test_load_rules_should_load_default_rules_when_no_rules_file_is_provided(self):
        rules = load_rules()
        self.assertEqual(rules, self.default_rules['Headers'])

    def test_load_rules_should_load_custom_rules_when_a_rules_file_is_provided(self):
        with open(os.path.join(os.path.dirname(__file__), '../test_resources/custom_rules.yml')) as f:
            rules = load_rules(f)

        self.assertEqual(rules, self.custom_rules['Headers'])

    def test_load_rules_should_merge_custom_rules_with_default_rules_when_merge_flag_is_true(self):
        with open(os.path.join(os.path.dirname(__file__), '../test_resources/custom_rules.yml')) as f:
            rules = load_rules(f, True)

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
