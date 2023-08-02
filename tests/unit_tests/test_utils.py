#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Tests for `utils.py` file."""

import os

import responses
import unittest
import yaml

from drheader import utils


class TestUtils(unittest.TestCase):

    def setUp(self):
        with open(os.path.join(os.path.dirname(__file__), '../test_resources/default_rules.yml')) as f:
            self.default_rules = yaml.safe_load(f.read())
        with open(os.path.join(os.path.dirname(__file__), '../test_resources/custom_rules.yml')) as f:
            self.custom_rules = yaml.safe_load(f.read())
        with open(os.path.join(os.path.dirname(__file__), '../test_resources/custom_rules_merged.yml')) as f:
            self.custom_rules_merged = yaml.safe_load(f.read())

    def test_parse_policy__should_extract_standalone_directive(self):
        policy = "default-src 'none'; upgrade-insecure-requests"
        directives_list = utils.parse_policy(policy, ';', key_delimiter=' ', value_delimiter=' ')

        self.assertIn('upgrade-insecure-requests', directives_list)

    def test_parse_policy__should_extract_key_value_directive(self):
        policy = "default-src 'none'; upgrade-insecure-requests"
        directives_list = utils.parse_policy(policy, ';', key_delimiter=' ', value_delimiter=' ')

        expected = utils.KeyValueDirective('default-src', ["'none'"], "'none'")
        self.assertIn(expected, directives_list)

    def test_parse_policy__should_extract_raw_key_value_directive(self):
        policy = "default-src 'none'; upgrade-insecure-requests"
        directives_list = utils.parse_policy(policy, ';', key_delimiter=' ', value_delimiter=' ')

        self.assertIn("default-src 'none'", directives_list)

    def test_parse_policy__should_extract_all_values_for_key_value_directive_with_multiple_values(self):
        policy = "default-src 'none'; script-src https: 'unsafe-inline'"
        directives_list = utils.parse_policy(policy, ';', key_delimiter=' ', value_delimiter=' ')

        expected = utils.KeyValueDirective('script-src', ['https:', "'unsafe-inline'"], "https: 'unsafe-inline'")
        self.assertIn(expected, directives_list)

    def test_parse_policy__should_extract_keys_from_key_value_directives_when_keys_only_is_true(self):
        policy = "default-src 'none'"
        directives_list = utils.parse_policy(policy, ';', key_delimiter=' ', value_delimiter=' ', keys_only=True)

        self.assertIn('default-src', directives_list)

    def test_parse_policy__should_remove_strip_characters_from_directive_values(self):
        policy = "default-src 'none'; script-src 'unsafe-inline'"
        directives_list = utils.parse_policy(policy, ';', key_delimiter=' ', value_delimiter=' ', strip='\' ')

        expected = utils.KeyValueDirective('default-src', ['none'], "'none'")
        self.assertIn(expected, directives_list)

    def test_parse_policy__should_handle_repeated_delimiters(self):
        policy = "default-src 'none';;  ;;   script-src   'self'   'unsafe-inline';;"
        directives_list = utils.parse_policy(policy, ';', ' ', value_delimiter=' ')

        expected = utils.KeyValueDirective('script-src', ["'self'", "'unsafe-inline'"], "  'self'   'unsafe-inline'")
        self.assertIn(expected, directives_list)

    def test_load_rules_should_load_default_rules_when_no_rules_file_is_provided(self):
        rules = utils.load_rules()
        self.assertEqual(rules, self.default_rules['Headers'])

    def test_load_rules_should_load_custom_rules_when_a_rules_file_is_provided(self):
        with open(os.path.join(os.path.dirname(__file__), '../test_resources/custom_rules.yml')) as f:
            rules = utils.load_rules(f)

        self.assertEqual(rules, self.custom_rules['Headers'])

    def test_load_rules_should_merge_custom_rules_with_default_rules_when_merge_flag_is_true(self):
        with open(os.path.join(os.path.dirname(__file__), '../test_resources/custom_rules.yml')) as f:
            rules = utils.load_rules(f, True)

        self.assertEqual(rules, self.custom_rules_merged['Headers'])

    @responses.activate
    def test_get_rules_from_uri_should_return_rules_from_a_valid_uri(self):
        uri = 'http://localhost:8080/custom.yml'
        responses.add(responses.GET, uri, json=self.custom_rules, status=200)

        rules_file = utils.get_rules_from_uri(uri)
        rules = yaml.safe_load(rules_file.read())
        self.assertEqual(rules, self.custom_rules)

    @responses.activate
    def test_get_rules_from_uri_should_raise_an_error_when_no_content_is_found(self):
        uri = 'http://mydomain.com/custom.yml'
        responses.add(responses.GET, uri, status=404)

        with self.assertRaises(Exception) as e:
            utils.get_rules_from_uri(uri)

        self.assertEqual('No content retrieved from {}'.format(uri), str(e.exception))
