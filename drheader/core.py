import json

import requests
import validators

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

        self.headers = dict((k.lower(), v) for k, v in self.headers.items())
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
            self.__validate_rules(rule.lower(), config, header=rule)
            if 'Directives' in config and rule.lower() in self.headers:
                for d_rule, d_config in config['Directives'].items():
                    self.__validate_rules(d_rule.lower(), d_config, header=rule, directive=d_rule)
        return self.report

    def __validate_rule_and_value(self, rule, expected_value, header, directive):
        """
        Verify headers content matches provided config.

        :param rule: Name of rule to validate
        :param expected_value: Expected value of header.
        :param header: Name of header
        :param directive: Name of directive (optional)
        :return:
        """
        expected_value_list = [str(item).lower() for item in expected_value]
        if len(expected_value_list) == 1:
            expected_value_list = [item.strip(' ') for item in expected_value_list[0].split(self.delimiter)]

        if directive:
            error_type = 7
            rule_value = _to_dict(self.headers[header.lower()], ';', ' ')
        else:
            error_type = 1
            rule_value = self.headers

        if rule not in rule_value:
            self.__add_report_item(severity='high', rule=rule, error_type=error_type, header=header,
                                   directive=directive, expected=expected_value_list)
        else:
            rule_list = [item.strip(' ') for item in rule_value[rule.lower()].split(self.delimiter)]
            if not all(elem in expected_value_list for elem in rule_list):
                self.__add_report_item(severity='high', rule=rule, error_type=3, header=header, directive=directive,
                                       expected=expected_value_list, value=rule_value[rule])

    def __validate_not_exists(self, rule, header, directive):
        """
        Verify specified rule does not exist in loaded headers.

        :param rule: Name of rule to validate
        :param header: Name of header
        :param directive: Name of directive (optional)
        """
        if directive:
            error_type = 8
            headers = _to_dict(self.headers[header.lower()], ';', ' ')
        else:
            error_type = 2
            headers = self.headers

        if rule in headers:
            self.__add_report_item(severity='high', rule=rule, error_type=error_type, header=header,
                                   directive=directive)

    def __validate_exists(self, rule, header, directive):
        """
        Verify specified rule exists in loaded headers.

        :param rule: Name of rule to validate
        :param header: Name of header
        :param directive: Name of directive (optional)
        """
        if directive:
            error_type = 7
            headers = _to_dict(self.headers[header.lower()], ';', ' ')
        else:
            error_type = 1
            headers = self.headers

        if rule not in headers:
            self.__add_report_item(severity='high', rule=rule, error_type=error_type, header=header,
                                   directive=directive)

    def __validate_must_avoid(self, rule, config, header, directive):
        """
        Verify specified values do not exist in loaded headers.

        :param rule: Name of rule to validate
        :param config: Configuration rule-set to use
        :param header: Name of header
        :param directive: Name of directive (optional)
        """

        try:
            config['Must-Avoid'] = [item.lower() for item in config['Must-Avoid']]
            for avoid in config['Must-Avoid']:
                if directive:
                    rule_value = _to_dict(self.headers[header.lower()], ';', ' ')[rule]
                else:
                    rule_value = self.headers[rule]

                if avoid in rule_value and rule not in self.anomalies:
                    if rule == 'content-security-policy':
                        policy = _to_dict(self.headers[header.lower()], ';', ' ')
                        directive = list(policy.keys())[list(policy.values()).index(avoid)]
                    self.__add_report_item(severity='medium', rule=rule, error_type=5, header=header,
                                           directive=directive, avoid=config['Must-Avoid'], value=avoid)
        except KeyError:
            pass

    def __validate_must_contain(self, rule, config, header, directive):
        """
        Verify the provided header contains certain params.

        :param rule: Name of rule to validate
        :param config: Configuration rule-set to use
        :param header: Name of header
        :param directive: Name of directive (optional)
        """

        try:
            if 'Must-Contain-One' in config:
                config['Must-Contain-One'] = [item.lower() for item in config['Must-Contain-One']]
                contain = False
                if directive:
                    policy = _to_dict(self.headers[header.lower()], ';', ' ')
                    values = policy[rule].split(' ')
                else:
                    policy = self.headers[rule]
                    values = policy.split(self.delimiter)
                for value in values:
                    value = value.lstrip()
                    if value in config['Must-Contain-One']:
                        contain = True
                        break

                if not contain:
                    self.__add_report_item(severity='high', rule=rule, error_type=6, header=header, directive=directive,
                                           expected=config['Must-Contain-One'], value=config['Must-Contain-One'])

            elif 'Must-Contain' in config:
                config['Must-Contain'] = [item.lower() for item in config['Must-Contain']]
                if rule == 'set-cookie':
                    for cookie in self.headers[rule]:
                        for contain in config['Must-Contain']:
                            if contain not in cookie:
                                if contain == 'secure':
                                    severity = 'high'
                                else:
                                    severity = 'medium'
                                self.__add_report_item(
                                    severity=severity, rule=rule, error_type=4, header=header,
                                    expected=config['Must-Contain'], value=contain, cookie=cookie)
                else:
                    if directive:
                        rule_value = _to_dict(self.headers[header.lower()], ';', ' ')[rule]
                    else:
                        rule_value = self.headers[rule]
                    for contain in config['Must-Contain']:
                        if contain not in rule_value and rule not in self.anomalies:
                            self.__add_report_item(severity='medium', rule=rule, error_type=4, header=header,
                                                   directive=directive, expected=config['Must-Contain'], value=contain)
        except KeyError:
            pass

    def __validate_rules(self, rule, config, header, directive=None):
        """
        Entry point for validation.

        :param rule: Name of rule to validate
        :param config: Configuration rule-set to use
        :param header: Name of header
        :param directive: Name of directive (optional)
        """

        try:
            if config['Delimiter']:
                self.delimiter = config['Delimiter']
        except KeyError:
            self.delimiter = ';'
        if config['Required'] is True or (config['Required'] == 'Optional' and rule in self.headers):
            if config['Enforce']:
                self.__validate_rule_and_value(rule, config['Value'], header, directive)
            else:
                self.__validate_exists(rule, header, directive)
                self.__validate_must_contain(rule, config, header, directive)
                self.__validate_must_avoid(rule, config, header, directive)
        else:
            self.__validate_not_exists(rule, header, directive)

    def __add_report_item(
        self,
        severity,
        rule,
        error_type,
        header,
        directive=None,
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

        if error_type in (4, 5, 6):
            if rule == 'set-cookie':
                error['value'] = cookie
            else:
                if directive:
                    policy = _to_dict(self.headers[header.lower()], ';', ' ')
                    error['value'] = policy[directive.lower()].strip('\'')
                else:
                    error['value'] = self.headers[rule]
            error['anomaly'] = value
        self.report.append(error)
