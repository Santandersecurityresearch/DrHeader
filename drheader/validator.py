import json
import os

from requests.structures import CaseInsensitiveDict

from drheader.report import ReportItem, ErrorType as Error
from drheader.utils import parse_policy

POLICY_HEADERS = ['content-security-policy', 'feature-policy', 'permissions-policy']

with open(os.path.join(os.path.dirname(__file__), 'resources/delimiters.json')) as delimiters_file:
    DELIMITERS = CaseInsensitiveDict(json.load(delimiters_file))


def validate_exists(config, headers, header, directive=None):
    """
    Validate that an expected header or directive is present in the given headers
    :param config: The configuration of the exists rule
    :param headers: The headers against which to validate
    :param header: The header to validate
    :param directive: The directive to validate
    """
    delimiters = _get_delimiters(header, config)

    if directive:
        exist_item = directive
        validation_items = parse_policy(headers[header], **delimiters, keys_only=True)
    else:
        exist_item = header
        validation_items = headers.keys()

    validation_items = {str(item).strip().lower() for item in validation_items}

    if exist_item.strip().lower() not in validation_items:
        severity = config.get('severity', 'high')
        delimiter = delimiters['value_delimiter'] if directive else delimiters['item_delimiter']
        if 'value' in config:
            expected = _get_expected_values(config, 'value', delimiter)
            return ReportItem(severity, Error.REQUIRED, header, directive, expected=expected, delimiter=delimiter)
        if 'value-any-of' in config:
            expected = _get_expected_values(config, 'value-any-of', delimiter)
            return ReportItem(severity, Error.REQUIRED, header, directive, expected=expected, delimiter=delimiter)
        if 'value-one-of' in config:
            expected = _get_expected_values(config, 'value-one-of', delimiter)
            return ReportItem(severity, Error.REQUIRED, header, directive, expected=expected)
        else:
            return ReportItem(severity, Error.REQUIRED, header, directive)


def validate_not_exists(config, headers, header, directive=None):
    """
    Validate that an expected header or directive is not present in the given headers
    :param config: The configuration of the not-exists rule
    :param headers: The headers against which to validate
    :param header: The header to validate
    :param directive: The directive to validate
    """
    delimiters = _get_delimiters(header, config)

    if directive:
        not_exist_item = directive
        validation_items = parse_policy(headers[header], **delimiters, keys_only=True)
    else:
        not_exist_item = header
        validation_items = headers.keys()

    validation_items = {str(item).strip().lower() for item in validation_items}

    if not_exist_item.strip().lower() in validation_items:
        severity = config.get('severity', 'high')
        return ReportItem(severity, Error.DISALLOWED, header, directive)


def validate_value(config, item_value, header, directive=None):
    """
    Validate that a given header or directive matches a given value
    :param config: The configuration of the enforce-value rule
    :param item_value: The value of the header or directive against which to validate
    :param header: The header to validate
    :param directive: The directive to validate
    """
    delimiters = _get_delimiters(header, config)

    if directive:
        delimiter = delimiters['value_delimiter']
        kvd = _get_directive(directive, parse_policy(item_value, **delimiters, key_values_only=True))
        validation_items, raw_value = kvd.value, kvd.raw_value
    else:
        delimiter = delimiters['item_delimiter']
        validation_items = [item.strip(delimiters.get('strip_items')) for item in item_value.split(delimiter)]
        raw_value = item_value

    expected = _get_expected_values(config, 'value', delimiter)

    if config.get('preserve-order'):
        validation_items = [str(item).strip().lower() for item in validation_items]
        expected_lower = [item.lower() for item in expected]
    else:
        validation_items = {str(item).strip().lower() for item in validation_items}
        expected_lower = {item.lower() for item in expected}

    if validation_items != expected_lower:
        severity = config.get('severity', 'high')
        return ReportItem(severity, Error.VALUE, header, directive, raw_value, expected=expected, delimiter=delimiter)


def validate_value_any_of(config, item_value, header, directive=None):
    """
    Validate that a given header or directive matches a given value
    :param config: The configuration of the enforce-value rule
    :param item_value: The value of the header or directive against which to validate
    :param header: The header to validate
    :param directive: The directive to validate
    """
    delimiters = _get_delimiters(header, config)

    if directive:
        delimiter = delimiters['value_delimiter']
        kvd = _get_directive(directive, parse_policy(item_value, **delimiters, key_values_only=True))
        validation_items, raw_value = kvd.value, kvd.raw_value
    else:
        delimiter = delimiters['item_delimiter']
        validation_items = [item.strip(delimiters.get('strip_items')) for item in item_value.split(delimiter)]
        raw_value = item_value

    validation_items = {str(item).strip().lower() for item in validation_items}
    accepted = _get_expected_values(config, 'value-any-of', delimiter)
    accepted_lower = [item.lower() for item in accepted]
    anomalies = []

    for item in validation_items:
        if item not in accepted_lower:
            anomalies.append(item)

    if anomalies:
        severity = config.get('severity', 'high')
        return ReportItem(severity, Error.VALUE_ANY, header, directive, raw_value, expected=accepted,
                          delimiter=delimiter, anomalies=anomalies)


def validate_value_one_of(config, item_value, header, directive=None):
    """
    Validate that a given header or directive matches a given value
    :param config: The configuration of the enforce-value rule
    :param item_value: The value of the header or directive against which to validate
    :param header: The header to validate
    :param directive: The directive to validate
    """
    delimiters = _get_delimiters(header, config)

    if directive:
        delimiter = delimiters['value_delimiter']
        kvd = _get_directive(directive, parse_policy(item_value, **delimiters, split_value=False, key_values_only=True))
        item_value, raw_value = kvd.value[0], kvd.raw_value
    else:
        delimiter = delimiters['item_delimiter']
        raw_value = item_value

    accepted = _get_expected_values(config, 'value-one-of', delimiter)

    if str(item_value).strip(delimiters.get('strip_items')).lower() not in {item.lower() for item in accepted}:
        severity = config.get('severity', 'high')
        return ReportItem(severity, Error.VALUE_ONE, header, directive, raw_value, expected=accepted)


def validate_must_avoid(config, item_value, header, directive=None):
    """
    Validate that a given header or directive does not contain any of a list of values
    :param config: The configuration of the must-avoid rule
    :param item_value: The value of the header or directive against which to validate
    :param header: The header to validate
    :param directive: The directive to validate
    """
    delimiters = _get_delimiters(header, config)

    if directive:
        delimiter = delimiters['value_delimiter']
        kvd = _get_directive(directive, parse_policy(item_value, **delimiters, key_values_only=True))
        validation_items, raw_value = kvd.value, kvd.raw_value
    else:
        if header.strip().lower() in POLICY_HEADERS:
            return _validate_must_avoid_for_policy_header(config, item_value, header, delimiters)
        delimiter = delimiters['item_delimiter']
        validation_items = item_value.split(delimiter) + parse_policy(item_value, **delimiters, keys_only=True)
        raw_value = item_value

    validation_items = {str(item).strip().lower() for item in validation_items}
    disallowed = _get_expected_values(config, 'must-avoid', delimiter)
    anomalies = []

    for avoid in disallowed:
        if avoid.lower() in validation_items:
            anomalies.append(avoid)

    if anomalies:
        severity = config.get('severity', 'medium')
        return ReportItem(severity, Error.AVOID, header, directive, raw_value, avoid=disallowed, anomalies=anomalies)


def validate_must_contain(config, item_value, header, directive=None):
    """
    Validate that a given header or directive contains all of a list of expected values
    :param config: The configuration of the must-contain-one rule
    :param item_value: The value of the header or directive against which to validate
    :param header: The header to validate
    :param directive: The directive to validate
    """
    delimiters = _get_delimiters(header, config)

    if directive:
        delimiter = delimiters['value_delimiter']
        kvd = _get_directive(directive, parse_policy(item_value, **delimiters, key_values_only=True))
        validation_items, raw_value = kvd.value, kvd.raw_value
    else:
        delimiter = delimiters['item_delimiter']
        validation_items = item_value.split(delimiter) + parse_policy(item_value, **delimiters, keys_only=True)
        raw_value = item_value

    validation_items = {str(item).strip().lower() for item in validation_items}
    expected = _get_expected_values(config, 'must-contain', delimiter)
    anomalies = []

    for contain in expected:
        if contain.lower() not in validation_items:
            anomalies.append(contain)

    if anomalies:
        severity = config.get('severity', 'medium')
        return ReportItem(severity, Error.CONTAIN, header, directive, raw_value, expected=expected, delimiter=delimiter,
                          anomalies=anomalies)


def validate_must_contain_one(config, item_value, header, directive=None):
    """
    Validate that a given header or directive contains at least one of a list of expected values
    :param config: The configuration of the must-contain-one rule
    :param item_value: The value of the header or directive against which to validate
    :param header: The header to validate
    :param directive: The directive to validate
    """
    delimiters = _get_delimiters(header, config)

    if directive:
        delimiter = delimiters['value_delimiter']
        kvd = _get_directive(directive, parse_policy(item_value, **delimiters, key_values_only=True))
        validation_items, raw_value = kvd.value, kvd.raw_value
    else:
        delimiter = delimiters['item_delimiter']
        validation_items = item_value.split(delimiter) + parse_policy(item_value, **delimiters, keys_only=True)
        raw_value = item_value

    validation_items = {str(item).strip().lower() for item in validation_items}
    expected = _get_expected_values(config, 'must-contain-one', delimiter)

    if not any(contain.lower() in validation_items for contain in expected):
        severity = config.get('severity', 'high')
        return ReportItem(severity, Error.CONTAIN_ONE, header, directive, raw_value, expected=expected)


def _validate_must_avoid_for_policy_header(config, item_value, header, delimiters):
    directives_list = parse_policy(item_value, **delimiters)
    validation_items = item_value.split(delimiters['item_delimiter'])

    for item in directives_list:
        try:
            validation_items.append(item.key)
            validation_items += [value for value in item.value]
        except AttributeError:
            validation_items.append(item)

    validation_items = {str(item).strip().lower() for item in validation_items}
    disallowed = _get_expected_values(config, 'must-avoid', delimiters['item_delimiter'])
    severity = config.get('severity', 'medium')
    anomalies, ncd_items, report_items = [], {}, []

    for avoid in disallowed:
        if avoid.lower() in validation_items:
            non_compliant_directives = []
            for item in directives_list:
                try:
                    if avoid in item.value:
                        non_compliant_directives.append(item)
                except AttributeError:
                    pass

            if not non_compliant_directives:
                anomalies.append(avoid)
            else:
                for ncd in non_compliant_directives:
                    directive, value = ncd.key, ncd.raw_value
                    item = {'value': value, 'anomalies': ncd_items.get(directive, {}).get('anomalies', []) + [avoid]}
                    ncd_items[directive] = item

    if anomalies:
        item = ReportItem(severity, Error.AVOID, header, value=item_value, avoid=disallowed, anomalies=anomalies)
        report_items.append(item)
    if ncd_items:
        for directive in ncd_items:
            value, anomalies = ncd_items[directive]['value'], ncd_items[directive]['anomalies']
            item = ReportItem(severity, Error.AVOID, header, directive, value, avoid=disallowed, anomalies=anomalies)
            report_items.append(item)
    return report_items


def _get_delimiters(header, config):
    delimiters = DELIMITERS.get(header.strip(), CaseInsensitiveDict())

    delimiters['item_delimiter'] = config.get('item-delimiter', delimiters.get('item_delimiter', None))
    delimiters['key_delimiter'] = config.get('key-delimiter', delimiters.get('key_delimiter', None))
    delimiters['value_delimiter'] = config.get('value-delimiter', delimiters.get('value_delimiter', None))
    delimiters['strip_items'] = delimiters.get('strip_items', None)
    return delimiters


def _get_directive(directive_name, directives_list):
    return next(item for item in directives_list if item.key.lower() == directive_name.lower())


def _get_expected_values(config, key, delimiter):
    if isinstance(config[key], list):
        return [str(item).strip() for item in config[key]]
    else:
        return [item.strip() for item in str(config[key]).split(delimiter)]
