import json

import requests
import validators
from requests.structures import CaseInsensitiveDict

from drheader.utils import load_rules, _to_dict


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
        6: 'Must-Contain-One directive missed',
        7: 'Directive not included in response',
        8: 'Directive should not be returned'
    }

    def __init__(
        self,
        url=None,
        method="GET",
        headers=None,
        status_code=None,
        params=None,
        request_headers=None,
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
        :param params: Request params
        :type params: dict
        :param request_headers: Request headers
        :type request_headers: dict
        :param verify: Verify the server's TLS certificate
        :type verify: bool or str
        """
        if request_headers is None:
            request_headers = {}
        if isinstance(headers, str):
            headers = json.loads(headers)
        elif url and not headers:
            headers, status_code = self._get_headers(url, method, params, request_headers, verify)

        self.status_code = status_code
        self.headers = CaseInsensitiveDict(headers)
        self.anomalies = []
        self.url = url
        self.delimiter = ';'
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
            self.__validate_rules(config, header=rule)
            if 'Directives' in config and rule in self.headers:
                for directive, d_config in config['Directives'].items():
                    self.__validate_rules(d_config, header=rule, directive=directive)
        return self.report

    def __validate_rule_and_value(self, expected_value, header, directive):
        """
        Verify headers content matches provided config.

        :param expected_value: Expected value of header.
        :param header: Name of header
        :param directive: Name of directive (optional)
        :return:
        """
        expected_value_list = [str(item).lower() for item in expected_value]
        if len(expected_value_list) == 1:
            expected_value_list = [item.strip(' ') for item in expected_value_list[0].split(self.delimiter)]

        if directive:
            rule = directive
            headers = _to_dict(self.headers[header], ';', ' ')
        else:
            rule = header
            headers = self.headers

        if rule not in headers:
            self.__add_report_item(
                severity='high',
                error_type=7 if directive else 1,
                header=header,
                directive=directive,
                expected=expected_value_list)
        else:
            rule_list = [item.strip(' ') for item in headers[rule].split(self.delimiter)]
            if not all(elem in expected_value_list for elem in rule_list):
                self.__add_report_item(
                    severity='high',
                    error_type=3,
                    header=header,
                    directive=directive,
                    expected=expected_value_list,
                    value=headers[rule])

    def __validate_not_exists(self, header, directive):
        """
        Verify specified rule does not exist in loaded headers.

        :param header: Name of header
        :param directive: Name of directive (optional)
        """

        if directive:
            rule = directive
            headers = _to_dict(self.headers[header], ';', ' ')
        else:
            rule = header
            headers = self.headers

        if rule in headers:
            self.__add_report_item(
                severity='high',
                error_type=8 if directive else 2,
                header=header,
                directive=directive)

    def __validate_exists(self, header, directive):
        """
        Verify specified rule exists in loaded headers.

        :param header: Name of header
        :param directive: Name of directive (optional)
        """
        if directive:
            rule = directive
            headers = _to_dict(self.headers[header], ';', ' ')
        else:
            rule = header
            headers = self.headers

        if rule not in headers:
            self.__add_report_item(
                severity='high',
                error_type=7 if directive else 1,
                header=header,
                directive=directive)

        return rule in headers  # Return value to prevent subsequent avoid/contain checks if the header is not present

    def __validate_must_avoid(self, config, header, directive):
        """
        Verify specified values do not exist in loaded headers.

        :param config: Configuration rule-set to use
        :param header: Name of header
        :param directive: Name of directive (optional)
        """
        if directive:
            rule = directive
            header_value = _to_dict(self.headers[header], ';', ' ')[rule]
        else:
            rule = header
            header_value = self.headers[rule]

        config['Must-Avoid'] = [item.lower() for item in config['Must-Avoid']]

        for avoid_value in config['Must-Avoid']:
            if avoid_value in header_value and rule not in self.anomalies:
                if rule.lower() == 'content-security-policy':
                    policy = _to_dict(self.headers[header], ';', ' ')
                    non_compliant_values = [item for item in list(policy.values()) if avoid_value in item]
                    indices = [list(policy.values()).index(item) for item in non_compliant_values]
                    for index in indices:
                        self.__add_report_item(
                            severity='medium',
                            error_type=5,
                            header=header,
                            directive=list(policy.keys())[index],
                            avoid=config['Must-Avoid'],
                            value=avoid_value)
                else:
                    self.__add_report_item(
                        severity='medium',
                        error_type=5,
                        header=header,
                        directive=directive,
                        avoid=config['Must-Avoid'],
                        value=avoid_value)

    def __validate_must_contain(self, config, header, directive):
        """
        Verify the provided header contains certain params.

        :param config: Configuration rule-set to use
        :param header: Name of header
        :param directive: Name of directive (optional)
        """
        if directive:
            rule = directive
            header_value = _to_dict(self.headers[header], ';', ' ')[rule]
        else:
            rule = header
            header_value = self.headers[rule]

        if 'Must-Contain-One' in config:
            config['Must-Contain-One'] = [item.lower() for item in config['Must-Contain-One']]
            contain_values = header_value.split(' ') if directive else header_value.split(self.delimiter)
            does_contain = False

            for contain_value in contain_values:
                contain_value = contain_value.lstrip()
                if contain_value in config['Must-Contain-One']:
                    does_contain = True
                    break
            if not does_contain:
                self.__add_report_item(
                    severity='high',
                    error_type=6,
                    header=header,
                    directive=directive,
                    expected=config['Must-Contain-One'],
                    value=config['Must-Contain-One'])

        elif 'Must-Contain' in config:
            config['Must-Contain'] = [item.lower() for item in config['Must-Contain']]
            if header.lower() == 'set-cookie':
                for cookie in self.headers[header]:
                    for contain_value in config['Must-Contain']:
                        if contain_value not in cookie:
                            self.__add_report_item(
                                severity='high' if contain_value == 'secure' else 'medium',
                                error_type=4,
                                header=header,
                                expected=config['Must-Contain'],
                                value=contain_value,
                                cookie=cookie)
            else:
                for contain_value in config['Must-Contain']:
                    if contain_value not in header_value and rule not in self.anomalies:
                        self.__add_report_item(
                            severity='medium',
                            error_type=4,
                            header=header,
                            directive=directive,
                            expected=config['Must-Contain'],
                            value=contain_value)

    def __validate_rules(self, config, header, directive=None):
        """
        Entry point for validation.

        :param config: Configuration rule-set to use
        :param header: Name of header
        :param directive: Name of directive (optional)
        """
        try:
            self.delimiter = config['Delimiter']
        except KeyError:
            self.delimiter = ';'

        if config['Required'] is True or (config['Required'] == 'Optional' and header in self.headers):
            if config['Enforce']:
                self.__validate_rule_and_value(config['Value'], header, directive)
            else:
                exists = self.__validate_exists(header, directive)
                if exists:
                    if 'Must-Contain-One' in config or 'Must-Contain' in config:
                        self.__validate_must_contain(config, header, directive)
                    if 'Must-Avoid' in config:
                        self.__validate_must_avoid(config, header, directive)
        elif config['Required'] is False:
            self.__validate_not_exists(header, directive)

    def __add_report_item(self, severity, error_type, header, directive=None, expected=None, avoid=None, value='',
                          cookie=''):
        """
        Add a entry to report.

        :param severity: [low, medium, high]
        :type severity: str
        :param error_type: [1...6] related to error_types
        :type error_type: int
        :param expected: Expected value of header
        :param avoid: Avoid value of header
        :param value: Current value of header
        :param cookie: Value of cookie (if applicable)
        """
        if directive:
            error = {'rule': header + ' - ' + directive, 'severity': severity, 'message': self.error_types[error_type]}
        else:
            error = {'rule': header, 'severity': severity, 'message': self.error_types[error_type]}

        if expected:
            error['expected'] = expected
            error['delimiter'] = self.delimiter
        if avoid:
            error['avoid'] = avoid
            error['delimiter'] = self.delimiter

        if error_type == 3:
            error['value'] = value
        elif error_type in (4, 5, 6):
            if header.lower() == 'set-cookie':
                error['value'] = cookie
            else:
                if directive:
                    error['value'] = _to_dict(self.headers[header], ';', ' ')[directive].strip('\'')
                else:
                    error['value'] = self.headers[header]
            error['anomaly'] = value
        self.report.append(error)
