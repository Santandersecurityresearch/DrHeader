import json

import requests
import validators

from drheader.utils import load_rules


class Drheader:
    """
    Core functionality for DrHeader. This is where the magic happens
    """
    error_types = {
        1: 'Header not included in response',
        2: 'Header should not be returned',
        3: 'Value does not match security policy',
        4: 'Must-Contain directive missed',
        5: 'Must-Avoid directive included',
        6: 'Must-Contain-One directive missed'
    }

    def __init__(
        self,
        url=None,
        method="GET",
        headers=None,
        status_code=None,
        post=None,
        params=None,
        request_headers={},
        verify=True
    ):
        """
        NOTE: at least one param required.

        :param url: (optional) URL of target
        :type url: str
        :param method: (optional) Method to use when doing the request
        :type method: str
        :param headers: (optional) Override headers
        :type headers: dict
        :param status_code: Override status code
        :type status_code: int
        :param post: Use post for request
        :type post: bool
        :param params: Request params
        :type params: dict
        :param request_headers: Request headers
        :type request_headers: dict
        :param verify: Verify the server's TLS certificate
        :type verify: bool or str
        """

        self.status_code = status_code
        self.headers = headers
        self.anomalies = []
        self.url = url
        self.delimiter = ';'

        if isinstance(headers, str):
            self.headers = json.loads(headers)

        if self.url and not self.headers:
            self.headers, self.status_code = self._get_headers(
                url, method, params, request_headers, verify
            )

        # self.headers_lower = dict((k.lower(), v.lower()) for k, v in self.headers.items())
        self.report = []

    @staticmethod
    def _get_headers(url, method, params, request_headers, verify):
        """
        Get headers for specified url.

        :param url: URL of target
        :type url: str
        :param method: (optional) Method to use when doing the request
        :type method: str
        :param params: Request params
        :type params: dict
        :param request_headers: Request headers
        :type request_headers: dict
        :param verify: Verify the server's TLS certificate
        :type verify: bool or str
        :return: headers, status_code
        :rtype: dict, int
        """

        if validators.url(url):
            req_obj = getattr(requests, method.lower())
            r = req_obj(url, data=params, headers=request_headers, verify=verify)

            headers = r.headers
            if len(r.raw.headers.getlist('Set-Cookie')) > 0:
                headers['set-cookie'] = r.raw.headers.getlist('Set-Cookie')
            return headers, r.status_code

    def analyze(self, rules=None):
        """
        Analyze the currently loaded headers against provided rules.

        :param rules: Override rules to compare headers against
        :type rules: dict
        :return: Audit report
        :rtype: list
        """

        for header, value in self.headers.items():
            if type(value) == str:
                self.headers[header] = value.lower()
            if type(value) == list:
                value = [item.lower() for item in value]
                self.headers[header] = value

        if not rules:
            rules = load_rules()
        for rule, config in rules.items():
            self.__validate_rules(rule, config)
        return self.report

    def __validate_rule_and_value(self, rule, expected_value):
        """
        Verify headers content matches provided config.

        :param rule: Name of header to validate.
        :param expected_value: Expected value of header.
        :return:
        """
        expected_value = [item.lower() for item in expected_value]
        expected_value_list = expected_value
        if len(expected_value) == 1:
            expected_value_list = [item.strip(' ') for item in expected_value[0].split(self.delimiter)]

        if rule not in self.headers:
            self.__add_report_item(
                severity='high',
                rule=rule,
                error_type=1,
                expected=expected_value_list
            )
        else:
            rule_list = [item.strip(' ') for item in self.headers[rule].split(self.delimiter)]
            if not all(elem in expected_value_list for elem in rule_list):
                # if not expected_value_list in rule_list:
                self.__add_report_item(
                    severity='high',
                    rule=rule,
                    error_type=3,
                    expected=expected_value_list,
                    value=self.headers[rule]
                )

    def __validate_not_exists(self, rule):
        """
        Verify specified rule does not exist in loaded headers.

        :param rule: Name of header to validate.
        """

        if rule in self.headers:
            self.__add_report_item(
                severity='high',
                rule=rule,
                error_type=2
            )

    def __validate_exists(self, rule):
        """
        Verify specified rule exists in loaded headers.

        :param rule: Name of header to validate.
        """
        if rule not in self.headers:
            self.__add_report_item(
                severity='high',
                rule=rule,
                error_type=1
            )

    def __validate_must_avoid(self, rule, config):
        """
        Verify specified values do not exist in loaded headers.

        :param rule: Name of header to validate.
        :param config: Configuration rule-set to use.
        """

        try:
            config['Must-Avoid'] = [item.lower() for item in config['Must-Avoid']]
            for avoid in config['Must-Avoid']:
                if avoid in self.headers[rule] and rule not in self.anomalies:
                    self.__add_report_item(
                        severity='medium',
                        rule=rule,
                        error_type=5,
                        avoid=config['Must-Avoid'],
                        value=avoid
                    )
        except KeyError:
            pass

    def __validate_must_contain(self, rule, config):
        """
        Verify the provided header contains certain params.

        :param rule: Name of header to validate.
        :param config: Configuration rule-set to use.
        """

        try:
            if 'Must-Contain-One' in config:
                config['Must-Contain-One'] = [item.lower() for item in config['Must-Contain-One']]
                contain = False
                if rule in self.headers:
                    policy = self.headers[rule]
                    directives = policy.split(self.delimiter)
                    for directive in directives:
                        directive = directive.lstrip()
                        if directive in config['Must-Contain-One']:
                            contain = True
                            break
                if not contain:
                    self.__add_report_item(
                        severity='high',
                        rule=rule,
                        error_type=6,
                        expected=config['Must-Contain-One'],
                        value=config['Must-Contain-One']
                    )
            elif 'Must-Contain' in config:
                config['Must-Contain'] = [item.lower() for item in config['Must-Contain']]
                if rule == 'Set-Cookie':
                    for cookie in self.headers[rule]:
                        for contain in config['Must-Contain']:
                            if contain not in cookie:
                                if contain == 'secure':
                                    self.__add_report_item(
                                        severity='high',
                                        rule=rule,
                                        error_type=4,
                                        expected=config['Must-Contain'],
                                        value=contain,
                                        cookie=cookie
                                    )
                                else:
                                    self.__add_report_item(
                                        severity='medium',
                                        rule=rule,
                                        error_type=4,
                                        expected=config['Must-Contain'],
                                        value=contain,
                                        cookie=cookie
                                    )
                else:
                    for contain in config['Must-Contain']:
                        if contain not in self.headers[rule] and rule not in self.anomalies:
                            self.__add_report_item(
                                severity='medium',
                                rule=rule,
                                error_type=4,
                                expected=config['Must-Contain'],
                                value=contain
                            )
        except KeyError:
            pass

    def __validate_rules(self, rule, config):
        """
        Entry point for validation.

        :param rule: Name of header (rule) to validate.
        :param config: Configuration rule-set to use.
        """

        try:
            if config['Delimiter']:
                self.delimiter = config['Delimiter']
        except KeyError:
            self.delimiter = ';'
        if config['Required'] is True or (config['Required'] == 'Optional' and rule in self.headers):
            if config['Enforce']:
                self.__validate_rule_and_value(rule, config['Value'])
            else:
                self.__validate_exists(rule)
                self.__validate_must_contain(rule, config)
                self.__validate_must_avoid(rule, config)
        else:
            self.__validate_not_exists(rule)

    def __add_report_item(
        self,
        severity,
        rule,
        error_type,
        expected=None,
        avoid=None,
        value='',
        cookie=''
    ):
        """
        Add a entry to report.

        :param severity: [low, medium, high]
        :type severity: str
        :param rule: Name of header/rule
        :type rule: str
        :param error_type: [1...6] related to error_types
        :type error_type: int
        :param expected: Expected value of header
        :param avoid: Avoid value of header
        :param value: Current value of header
        :param cookie: Value of cookie (if applicable)
        """

        error = {'rule': rule, 'severity': severity,
                 'message': self.error_types[error_type]}

        if expected:
            error['expected'] = expected
            error['delimiter'] = self.delimiter
        if avoid:
            error['avoid'] = avoid
            error['delimiter'] = self.delimiter
        if error_type == 3:
            error['value'] = value

        if error_type in (4, 5, 6):
            if rule == 'Set-Cookie':
                error['value'] = cookie
            else:
                error['value'] = self.headers[rule]
            error['anomaly'] = value
        self.report.append(error)
