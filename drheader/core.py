import json

import requests
import validators
from requests.structures import CaseInsensitiveDict

from drheader.report import Reporter
from drheader.utils import load_rules, parse_policy
from drheader.validator import DELIMITERS, validate_exists, validate_not_exists, validate_must_avoid, \
    validate_must_contain, validate_must_contain_one, validate_value, validate_value_any_of, validate_value_one_of


class Drheader:

    def __init__(self, headers=None, url=None, method='get', params=None, request_headers=None, verify=True):
        """
        Initialise a Drheader instance
        :param dict headers: The headers to analyse
        :param str url: The URL from which to retrieve the headers for analysis
        :param str method: The HTTP method to use to retrieve the headers for analysis
        :param dict params: Any request parameters to send when retrieving the headers for analysis
        :param dict request_headers: Any request headers to send when retrieving the headers for analysis
        :param bool verify: A flag to verify the server's TLS certificate
        """
        if not headers:
            if not url:
                raise ValueError("Nothing provided for analysis. Either 'headers' or 'url' must be defined")
            else:
                headers = self._get_headers(url, method, params, request_headers, verify)

        if isinstance(headers, str):
            self.headers = CaseInsensitiveDict(json.loads(headers))
        else:
            self.headers = CaseInsensitiveDict(headers)
        self.reporter = Reporter()

    def analyze(self, rules=None):
        """
        Analyse the loaded headers against the provided ruleset
        :param dict rules: The ruleset to validate the headers against
        """
        if not rules:
            rules = load_rules()
        for header, config in rules.items():
            if header.lower() != 'set-cookie':
                self._analyze(config, header)
            elif header in self.headers:
                for cookie in self.headers[header]:
                    self._analyze(config, header, cookie)
        return self.reporter.report

    def _analyze(self, config, header, cookie=None):
        config = CaseInsensitiveDict(config)
        self._validate_rules(config, header, cookie)

        if 'directives' in config and header in self.headers:
            for directive, d_config in config['directives'].items():
                config = CaseInsensitiveDict(d_config)
                self._validate_rules(config, header, cookie, directive=directive)

    def _validate_rules(self, config, header, cookie, directive=None):
        is_required = str(config['required']).strip().lower()

        if is_required == 'false':
            report_item = validate_not_exists(config, self.headers, header, directive)
            self._add_to_report_if_exists(report_item)
        else:
            exists = self._validate_exists(is_required, config, header, directive)
            if exists:
                header_value = cookie if cookie else self.headers[header]
                self._validate_enforced_value(config, header_value, header, directive)
                self._validate_avoid_and_contain_values(config, header_value, header, directive)

    def _validate_exists(self, is_required, config, header, directive):
        if is_required == 'true':
            report_item = validate_exists(config, self.headers, header, directive)
            self._add_to_report_if_exists(validate_exists(config, self.headers, header, directive))
            return bool(not report_item)
        if directive:
            return directive in parse_policy(self.headers[header], **DELIMITERS[header], keys_only=True)
        else:
            return header in self.headers

    def _validate_enforced_value(self, config, header_value, header, directive):
        if 'value' in config:
            report_item = validate_value(config, header_value, header, directive)
            self._add_to_report_if_exists(report_item)
        if 'value-any-of' in config:
            report_item = validate_value_any_of(config, header_value, header, directive)
            self._add_to_report_if_exists(report_item)
        if 'value-one-of' in config:
            report_item = validate_value_one_of(config, header_value, header, directive)
            self._add_to_report_if_exists(report_item)

    def _validate_avoid_and_contain_values(self, config, header_value, header, directive):
        if 'must-avoid' in config:
            report_item = validate_must_avoid(config, header_value, header, directive)
            self._add_to_report_if_exists(report_item)
        if 'must-contain' in config:
            report_item = validate_must_contain(config, header_value, header, directive)
            self._add_to_report_if_exists(report_item)
        if 'must-contain-one' in config:
            report_item = validate_must_contain_one(config, header_value, header, directive)
            self._add_to_report_if_exists(report_item)

    def _add_to_report_if_exists(self, report_item):
        if report_item:
            try:
                self.reporter.add_item(report_item)
            except AttributeError:
                for item in report_item:
                    self.reporter.add_item(item)

    @staticmethod
    def _get_headers(url, method, params, headers, verify):
        if not validators.url(url):
            raise ValueError(f"Cannot retrieve headers from '{url}'. The URL is malformed")

        request_object = getattr(requests, method.lower())
        response = request_object(url, data=params, headers=headers, verify=verify)
        response_headers = response.headers

        if len(response.raw.headers.getlist('Set-Cookie')) > 0:
            response_headers['set-cookie'] = response.raw.headers.getlist('Set-Cookie')
        return response_headers
