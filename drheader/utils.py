# -*- coding: utf-8 -*-

"""Utils for drheader."""

import logging
import os

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


def load_rules(rule_file=None):
    """
    Loads drheader ruleset. Will load local defaults unless overridden.
    :param rule_file: file object of rules.
    :type rule_file: file
    :return: drheader rules
    :rtype: dict
    """

    if rule_file:
        logging.debug('')
        rules = yaml.safe_load(rule_file.read())
    else:
        with open(os.path.join(os.path.dirname(__file__), 'rules.yml'), 'r') as f:
            rules = yaml.safe_load(f.read())

    return rules['Headers']
