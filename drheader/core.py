"""Main module and entry point for analysis."""
import json
import logging
import os

import requests
from requests.structures import CaseInsensitiveDict

from drheader import utils
from drheader.report import Reporter
from drheader.validators.cookie_validator import CookieValidator
from drheader.validators.directive_validator import DirectiveValidator
from drheader.validators.header_validator import HeaderValidator

_ALLOWED_HTTP_METHODS = ['delete', 'get', 'head', 'options', 'patch', 'post', 'put']
_CROSS_ORIGIN_HEADERS = ['cross-origin-embedder-policy', 'cross-origin-opener-policy']

with open(os.path.join(os.path.dirname(__file__), 'resources/delimiters.json')) as delimiters:
    _DELIMITERS = CaseInsensitiveDict(json.load(delimiters))


class Drheader:
    """Main class and entry point for analysis.

    Attributes:
        headers (CaseInsensitiveDict): The headers to analyse.
        cookies (CaseInsensitiveDict): The cookies to analyse.
        reporter (Reporter): Reporter instance that generates and holds the final report.
    """

    def __init__(self, headers=None, url=None, **kwargs):
        """Initialises a Drheader instance.

        At least one of <headers> and <url> must be defined. The value passed in <headers> is treated differently
        depending on whether a URL is provided. If a URL is provided, the headers passed are treated as request headers
        and are sent with the HTTP request to <url>. Otherwise, they are the raw headers that are analysed.

        Args:
            headers (dict): Either headers to analyse or a dict of headers to send with the request to <url>.
            url (str): URL from which to retrieve the headers to analyse.

        Raises:
            ValueError: If neither headers nor url is provided, or if url is not a valid URL.
        """
        if not url:
            if not headers:
                raise ValueError("Nothing provided for analysis. Either 'headers' or 'url' must be defined")
            else:
                headers_to_analyse = json.loads(headers) if isinstance(headers, str) else headers
        else:
            headers_to_analyse = _get_headers_from_url(url, headers=headers, **kwargs)

        self.cookies = CaseInsensitiveDict()
        self.headers = CaseInsensitiveDict(headers_to_analyse)
        self.reporter = Reporter()

        for cookie in self.headers.get('set-cookie', []):
            cookie = cookie.split('=', 1)
            self.cookies[cookie[0]] = cookie[1]

    def analyze(self, rules=None, cross_origin_isolated=False):
        """Analyses headers against a drHEADer ruleset.

        Args:
            rules (dict): (optional) The rules against which to assess the headers. Default rules are used if undefined.
            cross_origin_isolated (bool): (optional) A flag to enable cross-origin isolation rules. Default is False.

        Returns:
            A list containing all the rule violations found during analysis. The report consists of individual dict
            items per header and rule. Each item in the report will detail the non-compliant header, the rule violated
            and its associated severity, and, if applicable, the observed value of the header, any expected, disallowed
            or anomalous values, and the correct delimiter. For example:
            {
                'rule': 'Referrer-Policy',
                'message': 'Value does not match security policy. Exactly one of the expected items was expected',
                'severity': 'high',
                'value': 'origin-when-cross-origin'
                'expected': ['same-origin', 'strict-origin-when-cross-origin']
            }
        """
        if not rules:
            rules = _translate_to_case_insensitive_dict(utils.default_rules())
        else:
            rules = _translate_to_case_insensitive_dict(rules)

        header_validator = HeaderValidator(self.headers)
        directive_validator = DirectiveValidator(self.headers)
        cookie_validator = CookieValidator(self.cookies)

        for header, rule_config in rules.items():
            if header.lower() in _CROSS_ORIGIN_HEADERS and not cross_origin_isolated:
                logging.info(f"Cross-origin isolation validations are not enabled. Skipping header '{header}'")
                continue

            if header.lower() != 'set-cookie':
                self._validate_rules(rule_config, header_validator, header)
            elif header in self.headers:  # Validates global rules for cookies e.g. all cookies must contain 'secure'
                for cookie in self.cookies:
                    self._validate_rules(rule_config, cookie_validator, header, cookie=cookie)

            if 'directives' in rule_config and header in self.headers:
                for directive, directive_config in rule_config['directives'].items():
                    self._validate_rules(directive_config, directive_validator, header, directive=directive)
            if 'cookies' in rule_config and header.lower() == 'set-cookie':  # Validates individual rules for cookies e.g. cookie session_id must contain 'samesite=strict'  # noqa:E501
                for cookie, cookie_config in rule_config['cookies'].items():
                    self._validate_rules(cookie_config, cookie_validator, header, cookie=cookie)
        return self.reporter.report

    def _validate_rules(self, config, validator, header, **kwargs):
        """Validates rules for a single header, directive or cookie."""
        config['delimiters'] = _DELIMITERS.get(header)
        required = str(config['required']).strip().lower()

        if required == 'true':
            if report_item := validator.exists(config, header, **kwargs):
                self._add_to_report(report_item)
            else:
                self._validate_value_rules(config, validator, header, **kwargs)
        elif required == 'false':
            if report_item := validator.not_exists(config, header, **kwargs):
                self._add_to_report(report_item)
        elif required == 'optional':
            if cookie := kwargs.get('cookie'):
                is_present = cookie in self.cookies
            elif directive := kwargs.get('directive'):
                is_present = directive in utils.parse_policy(self.headers[header], **_DELIMITERS[header], keys_only=True)  # noqa: E501
            else:
                is_present = header in self.headers

            if is_present:
                self._validate_value_rules(config, validator, header, **kwargs)

    def _validate_value_rules(self, config, validator, header, **kwargs):
        """Validates rules for a single header, directive or cookie."""
        if 'value' in config:
            if report_item := validator.value(config, header, **kwargs):
                self._add_to_report(report_item)
        elif 'value-any-of' in config:
            if report_item := validator.value_any_of(config, header, **kwargs):
                self._add_to_report(report_item)
        elif 'value-one-of' in config:
            if report_item := validator.value_one_of(config, header, **kwargs):
                self._add_to_report(report_item)
        else:
            if 'must-avoid' in config:
                if report_item := validator.must_avoid(config, header, **kwargs):
                    self._add_to_report(report_item)
            if 'must-contain' in config:
                if report_item := validator.must_contain(config, header, **kwargs):
                    self._add_to_report(report_item)
            if 'must-contain-one' in config:
                if report_item := validator.must_contain_one(config, header, **kwargs):
                    self._add_to_report(report_item)

    def _add_to_report(self, report_item):
        """Adds a finding or list of findings to the final report."""
        try:
            self.reporter.add_item(report_item)
        except AttributeError:  # For must-avoid rules on policy headers (CSP, Permissions-Policy)
            for item in report_item:  # A separate report item is created for each directive that violates the must-avoid rule e.g. multiple directives containing 'unsafe-inline'  # noqa:E501
                self.reporter.add_item(item)


def _get_headers_from_url(url, method='head', **kwargs):
    """Retrieves headers from a URL."""
    if method.strip().lower() not in _ALLOWED_HTTP_METHODS:
        raise ValueError(f"'{method}' is not an allowed HTTP method")

    if 'timeout' not in kwargs:
        kwargs['timeout'] = 5
    if 'allow_redirects' not in kwargs:
        kwargs['allow_redirects'] = True

    response = requests.request(method, url, **kwargs)
    response_headers = response.headers
    response_headers['set-cookie'] = response.raw.headers.getlist('Set-Cookie')
    return response_headers


def _translate_to_case_insensitive_dict(dict_to_translate):
    """Recursively transforms a dict into a case-insensitive dict."""
    for key, value in dict_to_translate.items():
        if isinstance(value, dict):
            dict_to_translate[key] = _translate_to_case_insensitive_dict(value)
    return CaseInsensitiveDict(dict_to_translate)
