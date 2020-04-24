# -*- coding: utf-8 -*-

"""Utils for drheader."""

import logging
import os
import io
import requests
import yaml


def _to_lower_dict(some_dict):
    """Convert all keys to lowercase"""
    result = {}
    for key, value in some_dict.items():
        try:
            result[key.lower()] = value
        except AttributeError:
            result[key] = value
    return result


def load_rules(rule_file=None, merge=None):
    """
    Loads drheader ruleset. Will load local defaults unless overridden.
    If merge flag is present, result file will be a merge between local defaults and custom file
    :param rule_file: file object of rules.
    :type rule_file: file
    :param merge: flag indicating to merge file_rule with default rules
    :type rule_file: boolean
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
    Mege both rule set. Rules defined in 'custom_rules', also present in 'default_rules', will be overriden.
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


def get_rules_from_uri(URI):
    """
    Retrieves custom rule set from URL
    :param URI: URL to your custom rules file
    :type URI: uri
    :return: rules file
    :rtype: file
    """
    download = requests.get(URI)
    if not download.content:
        raise Exception('No content retrieved from {}'.format(URI))
    file = io.BytesIO(download.content)
    return file
