# -*- coding: utf-8 -*-

"""Utils for drheader."""

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
        strip (str): (optional) A string of characters to strip from policy values.
        keys_only (bool): (optional) A flag to return only keys from key-value directives. Default is False.
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
            rules = _merge_rules(default_rules, rules)
    else:
        with open(os.path.join(os.path.dirname(__file__), 'rules.yml'), 'r') as f:
            rules = yaml.safe_load(f.read())

    return rules['Headers']


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


def translate_to_case_insensitive_dict(dict_to_translate):
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
