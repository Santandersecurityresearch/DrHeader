# -*- coding: utf-8 -*-

"""Utils for drheader."""

import io
import logging
import os
from typing import NamedTuple

import requests
import yaml


class KeyValueDirective(NamedTuple):
    key: str
    value: list
    raw_value: str = None


def parse_policy(policy, item_delimiter, key_delimiter=None, value_delimiter=None, strip_items=None, split_value=True,
                 keys_only=False, key_values_only=False):
    """
    Parse a policy string into a list of individual directives
    :param str policy: The policy string to be parsed
    :param str item_delimiter: The character that delimits individual policy items
    :param str key_delimiter: The character that delimits the kay and value in key-value directives
    :param str value_delimiter: The character that delimits individual value items in key-value directives
    :param str strip_items: A string of characters to strip from directive values
    :param bool split_value: Split the value in a key-value directive into
    :param bool keys_only: Return only keys and standalone directives
    :param bool key_values_only: Return only key-value directives
    """
    if not item_delimiter:
        return [policy]
    if not key_delimiter:
        return policy.split(item_delimiter)

    policy_items = list(filter(lambda s: s.strip(), policy.strip().split(item_delimiter)))
    directives = []

    for item in policy_items:
        directive = list(item.strip(key_delimiter + ' ').split(key_delimiter, 1))
        key = directive[0].strip()
        if len(directive) == 1:
            if not key_values_only:
                directives.append(key)
        else:
            if keys_only:
                directives.append(key)
            else:
                directive = _extract_key_value_directive(directive, value_delimiter, strip_items, split_value)
                directives.append(directive)
    return directives


def load_rules(rule_file=None, merge=None):
    """
    Loads drheader ruleset. Will load local defaults unless overridden.
    If merge flag is present, result file will be a merge between local defaults and custom file
    :param rule_file: file object of rules.
    :type rule_file: file
    :param merge: flag indicating to merge file_rule with default rules
    :type merge: boolean
    :return: drheader rules
    :rtype: dict
    """

    if rule_file:
        logging.debug('')
        rules = yaml.safe_load(rule_file.read())
        if merge:
            with open(os.path.join(os.path.dirname(__file__), 'rules.yml'), 'r') as f:
                default_rules = yaml.safe_load(f.read())
            rules = merge_rules(default_rules, rules)
    else:
        with open(os.path.join(os.path.dirname(__file__), 'rules.yml'), 'r') as f:
            rules = yaml.safe_load(f.read())

    return rules['Headers']


def merge_rules(default_rules, custom_rules):
    """
    Merge both rule set. Rules defined in 'custom_rules', also present in 'default_rules', will be overridden.
    If a new rule is present in custom_rules, not present in default_rules, it will be added.
    :param default_rules: base file object of rules.
    :type default_rules: dict
    :param custom_rules: override file object of rules.
    :type custom_rules: dict
    :return: final rule
    :rtype: dict
    """

    for rule in custom_rules['Headers']:
        default_rules['Headers'][rule] = custom_rules['Headers'][rule]

    return default_rules


def get_rules_from_uri(uri):
    """
    Retrieves custom rule set from URL
    :param uri: URL to your custom rules file
    :type uri: uri
    :return: rules file
    :rtype: file
    """
    download = requests.get(uri)
    if not download.content:
        raise Exception('No content retrieved from {}'.format(uri))
    file = io.BytesIO(download.content)
    return file


def _extract_key_value_directive(directive, value_delimiter, strip_items, split_value):
    if value_delimiter and split_value:
        value_items = list(filter(lambda s: s.strip(), directive[1].split(value_delimiter)))
        value = [item.strip(strip_items) for item in value_items]
    else:
        value = [directive[1].strip(strip_items)]
    return KeyValueDirective(directive[0].strip(), value, directive[1])
