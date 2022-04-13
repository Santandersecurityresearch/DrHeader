# -*- coding: utf-8 -*-
"""Utility functions for core module."""
import io
import logging
import os
from typing import NamedTuple

import requests
import yaml
from requests import structures


class KeyValueDirective(NamedTuple):
    key: str
    value: list
    raw_value: str = None


def parse_policy(policy, item_delimiter=None, key_delimiter=None, value_delimiter=None, strip=None, keys_only=False):
    """Parses a policy string into a list of individual directives.

    Args:
        policy (str): The policy to be parsed.
        item_delimiter (str): (optional) The character that delimits individual directives.
        key_delimiter (str): (optional) The character that delimits keys and values in key-value directives.
        value_delimiter (str): (optional) The character that delimits individual values in key-value directives.
        strip (str): (optional) A string of characters to strip from directive values.
        keys_only (bool): (optional) A flag to return only keys from key-value directives. Default is False.

    Returns:
        A list of directives.
    """
    if not item_delimiter:
        return [policy.strip(strip)]
    elif not key_delimiter:
        return [item.strip(strip) for item in policy.strip().split(item_delimiter)]
    else:
        policy_items = [item for item in policy.strip().split(item_delimiter)]
        directives = []

    for item in policy_items:
        directives.append(item.strip())
        split_item = item.strip(key_delimiter).split(key_delimiter, 1)
        if len(split_item) == 2:
            if keys_only:
                directives.append(split_item[0].strip())
            else:
                key_value_directive = _extract_key_value_directive(split_item, value_delimiter, strip)
                directives.append(key_value_directive)
    return directives


def load_rules(rule_file=None, merge=False):
    """Returns a drHEADer ruleset from a file.

    The loaded ruleset can be configured to be merged with the default drHEADer rules. If a rule exists in both the
    custom rules and default rules, the custom one will take priority and override the default one. Otherwise, the new
    custom rule will be appended to the default rules. If no file is provided, the default rules will be returned.

    Args:
        rule_file (file): (optional) The YAML file containing the ruleset.
        merge (bool): (optional) A flag to merge the loaded rules with the drHEADer default rules. Default is False.

    Returns:
        A dict containing the loaded rules.
    """
    if rule_file:
        logging.debug('')
        rules = yaml.safe_load(rule_file.read())
        if merge:
            with open(os.path.join(os.path.dirname(__file__), 'rules.yml'), 'r') as f:
                default_rules = yaml.safe_load(f.read())
            rules = _merge_rules(default_rules, rules)
    else:
        with open(os.path.join(os.path.dirname(__file__), 'rules.yml'), 'r') as f:
            rules = yaml.safe_load(f.read())

    return rules['Headers']


def get_rules_from_uri(uri):
    """Retrieves a rules file from a URL."""
    download = requests.get(uri)
    if not download.content:
        raise Exception('No content retrieved from {}'.format(uri))
    file = io.BytesIO(download.content)
    return file


def translate_to_case_insensitive_dict(dict_to_translate):
    """Recursively transforms a dict into a case-insensitive dict."""
    for key, value in dict_to_translate.items():
        if isinstance(value, dict):
            dict_to_translate[key] = translate_to_case_insensitive_dict(value)
    return structures.CaseInsensitiveDict(dict_to_translate)


def _extract_key_value_directive(directive, value_delimiter, strip):
    if value_delimiter:
        value_items = list(filter(lambda s: s.strip(), directive[1].split(value_delimiter)))
        value = [item.strip(strip) for item in value_items]
    else:
        value = [directive[1].strip(strip)]
    return KeyValueDirective(directive[0].strip(), value, directive[1])


def _merge_rules(default_rules, custom_rules):
    for rule in custom_rules['Headers']:
        default_rules['Headers'][rule] = custom_rules['Headers'][rule]

    return default_rules
