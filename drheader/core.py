"""Main module and entry point for analysis."""
import json
import logging
import os

from requests.structures import CaseInsensitiveDict

from drheader import utils
from drheader.report import Reporter
from drheader.validators.cookie_validator import CookieValidator
from drheader.validators.directive_validator import DirectiveValidator
from drheader.validators.header_validator import HeaderValidator

_CROSS_ORIGIN_HEADERS = ['cross-origin-embedder-policy', 'cross-origin-opener-policy']

with open(os.path.join(os.path.dirname(__file__), 'resources/delimiters.json')) as delimiters:
    _DELIMITERS = utils.translate_to_case_insensitive_dict(json.load(delimiters))


class Drheader:
    """Main class and entry point for analysis.

    Attributes:
        headers (CaseInsensitiveDict): The headers to analyse.
        cookies (CaseInsensitiveDict): The cookies to analyse.
        reporter (Reporter): Reporter instance that generates and holds the final report.
    """

    def __init__(self, headers=None, url=None, method='get', params=None, request_headers=None, verify=True):
        """Initialises a Drheader instance.

        Either headers or url must be defined. If both are defined, the value passed in headers will take priority. If
        only url is defined, the headers will be retrieved from the HTTP response from the provided URL.

        Args:
            headers (dict | str): (optional) The headers to analyse. Must be valid JSON if passed as a string.
            url (str): (optional) The URL from which to retrieve the headers.
            method (str): (optional) The HTTP verb to use when retrieving the headers. Default is 'get'.
            params (dict): (optional) Any request parameters to send when retrieving the headers.
            request_headers (dict): (optional) Any request headers to send when retrieving the headers.
            verify (bool): (optional) A flag to verify the server's TLS certificate. Default is True.

        Raises:
            ValueError: If neither headers nor url is provided, or if url is not a valid URL.
        """
        if not headers:
            if not url:
                raise ValueError("Nothing provided for analysis. Either 'headers' or 'url' must be defined")
            else:
                headers = utils.get_headers_from_url(url, method, params, request_headers, verify)
        elif isinstance(headers, str):
            headers = json.loads(headers)

        self.cookies = CaseInsensitiveDict()
        self.headers = CaseInsensitiveDict(headers)
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
            rules = utils.translate_to_case_insensitive_dict(utils.load_rules())
        else:
            rules = utils.translate_to_case_insensitive_dict(rules)

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
        config['delimiters'] = _DELIMITERS.get(header)
        required = str(config['required']).strip().lower()

        if required == 'false':
            if report_item := validator.not_exists(config, header, **kwargs):
                self._add_to_report(report_item)
            return
        elif required == 'true':
            if report_item := validator.exists(config, header, **kwargs):
                self._add_to_report(report_item)
            else:
                self._validate_enforced_value(config, validator, header, **kwargs)
                self._validate_avoid_and_contain_values(config, validator, header, **kwargs)
        else:
            if (cookie := kwargs.get('cookie')) and cookie in self.cookies:
                self._validate_enforced_value(config, validator, header, cookie=cookie)
                self._validate_avoid_and_contain_values(config, validator, header, cookie=cookie)
            elif directive := kwargs.get('directive'):
                directives = utils.parse_policy(self.headers[header], **_DELIMITERS[header], keys_only=True)
                if directive in directives:
                    self._validate_enforced_value(config, validator, header, directive=directive)
                    self._validate_avoid_and_contain_values(config, validator, header, directive=directive)
            elif header in self.headers:
                self._validate_enforced_value(config, validator, header)
                self._validate_avoid_and_contain_values(config, validator, header)

    def _validate_enforced_value(self, config, validator, header, **kwargs):
        if 'value' in config:
            if report_item := validator.value(config, header, **kwargs):
                self._add_to_report(report_item)
        elif 'value-any-of' in config:
            if report_item := validator.value_any_of(config, header, **kwargs):
                self._add_to_report(report_item)
        elif 'value-one-of' in config:
            if report_item := validator.value_one_of(config, header, **kwargs):
                self._add_to_report(report_item)

    def _validate_avoid_and_contain_values(self, config, validator, header, **kwargs):
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
        try:
            self.reporter.add_item(report_item)
        except AttributeError:  # For must-avoid rules on policy headers (CSP, Permissions-Policy)
            for item in report_item:  # A separate report item is created for each directive that violates the must-avoid rule e.g. multiple directives containing 'unsafe-inline'  # noqa:E501
                self.reporter.add_item(item)
