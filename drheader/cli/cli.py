"""Console script for drheader."""
import ast
import json
import logging
import os
import sys
from json import JSONDecodeError

import click
import jsonschema
from click import Choice, File, ParamType

from drheader import Drheader, __version__
from drheader.cli import utils

_OUTPUT_TYPES = ['json', 'table']


class URLParamType(ParamType):

    name = 'URL'

    def convert(self, value, param, ctx):
        if not value.startswith('http'):
            scheme = click.prompt('Please select a scheme', type=Choice(['http', 'https'], case_sensitive=False))
            value = f'{scheme}://{value}'
        return value


@click.group(context_settings={'show_default': True})
@click.version_option(__version__, '--version', '-v')
def main():
    """Console script for drheader."""


@main.group()
def compare():
    """Compare headers with drheader."""


@main.group()
def scan():
    """Scan endpoints with drheader."""


@compare.command(context_settings={
    'default_map': {
        'output': 'table'
    }
})
@click.argument('file', type=File(), required=True)
@click.option('--cross-origin-isolated', '-co', is_flag=True, help='Enable cross-origin isolation validations')
@click.option('--debug', '-d', is_flag=True, help='Enable debug logging')
@click.option('--junit', '-j', is_flag=True, help='Generate a JUnit report')
@click.option('--merge', '-m', is_flag=True, help='Merge a custom ruleset with the default rules')
@click.option('--output', '-o', type=Choice(_OUTPUT_TYPES, case_sensitive=False), help='Report output format')
@click.option('--rules-file', '-rf', type=File(), help='Use a custom ruleset, loaded from file')
@click.option('--rules-uri', '-ru', metavar='URI', help='Use a custom ruleset, downloaded from URI')
def single(file, cross_origin_isolated, debug, junit, merge, output, rules_file, rules_uri):
    if debug:
        logging.basicConfig(level=logging.DEBUG)

    scanner = Drheader(headers=json.loads(file.read()))
    rules = utils.get_rules(rules_file=rules_file, rules_uri=rules_uri, merge_default=merge)
    report = scanner.analyze(rules=rules, cross_origin_isolated=cross_origin_isolated)

    if output == 'json':
        click.echo(json.dumps(report, indent=4))
    else:
        click.echo()
        if not report:
            click.echo('No issues found!')
        else:
            click.echo(f'{len(report)} issues found')
            click.echo(utils.tabulate_report(report))
    if junit:
        utils.file_junit_report(rules, report)

    sys.exit(os.EX_SOFTWARE if report else os.EX_OK)


@compare.command(context_settings={
    'default_map': {
        'output': 'table'
    }
})
@click.argument('file', type=File(), required=True)
@click.option('--cross-origin-isolated', '-co', is_flag=True, help='Enable cross-origin isolation validations')
@click.option('--debug', '-d', is_flag=True, help='Enable debug logging')
@click.option('--merge', '-m', is_flag=True, help='Merge a custom ruleset with the default rules')
@click.option('--output', '-o', type=Choice(_OUTPUT_TYPES, case_sensitive=False), help='Report output format')
@click.option('--rules-file', '-rf', type=File(), help='Use a custom ruleset, loaded from file')
@click.option('--rules-uri', '-ru', metavar='URI', help='Use a custom ruleset, downloaded from URI')
def bulk(file, cross_origin_isolated, debug, merge, output, rules_file, rules_uri):
    if debug:
        logging.basicConfig(level=logging.DEBUG)

    data = json.loads(file.read())
    with open(os.path.join(os.path.dirname(__file__), '../resources/cli/bulk_compare_schema.json')) as schema:
        schema = json.load(schema)
        jsonschema.validate(instance=data, schema=schema)

    audit = []
    rules = utils.get_rules(rules_file=rules_file, rules_uri=rules_uri, merge_default=merge)
    for target in data:
        try:
            scanner = Drheader(headers=target['headers'])
            report = scanner.analyze(rules=rules, cross_origin_isolated=cross_origin_isolated)
            audit.append({'url': target['url'], 'report': report})
        except Exception as e:
            audit.append({'url': target['url'], 'report': [], 'error': str(e)})

    if output == 'json':
        click.echo(json.dumps(audit, indent=4))
    else:
        for target in audit:
            click.echo()
            if target.get('error'):
                click.echo(f"{target['url']}: {target['error']}")
            elif not target['report']:
                click.echo(f"{target['url']}: No issues found!")
            else:
                click.echo(f"{target['url']}: {len(target['report'])} issues found")
                click.echo(utils.tabulate_report(target['report']))

    for target in audit:
        if target.get('report') or target.get('error'):
            sys.exit(os.EX_SOFTWARE)
    else:
        sys.exit(os.EX_OK)


@scan.command(context_settings={
    'default_map': {
        'output': 'table'
    },
    'ignore_unknown_options': True
})
@click.argument('target_url', type=URLParamType(), required=True)
@click.argument('request_args', type=click.UNPROCESSED, nargs=-1)
@click.option('--cross-origin-isolated', '-co', is_flag=True, help='Enable cross-origin isolation validations')
@click.option('--debug', '-d', is_flag=True, help='Enable debug logging')
@click.option('--junit', '-j', is_flag=True, help='Generate a JUnit report')
@click.option('--merge', '-m', is_flag=True, help='Merge a custom ruleset with the default rules')
@click.option('--output', '-o', type=Choice(_OUTPUT_TYPES, case_sensitive=False), help='Report output format')
@click.option('--rules-file', '-rf', type=File(), help='Use a custom ruleset, loaded from file')
@click.option('--rules-uri', '-ru', metavar='URI', help='Use a custom ruleset, downloaded from URI')
def single(target_url, request_args, cross_origin_isolated, debug, junit, merge, output, rules_file, rules_uri):  # noqa: E501, F811
    if debug:
        logging.basicConfig(level=logging.DEBUG)

    kwargs = {}
    for i in range(0, len(request_args), 2):
        key = request_args[i].strip('-').replace('-', '_')
        try:
            kwargs[key] = json.loads(request_args[i + 1])
        except JSONDecodeError:
            try:
                kwargs[key] = ast.literal_eval(request_args[i + 1])  # This handles bytes and tuples
            except (SyntaxError, ValueError):
                kwargs[key] = request_args[i + 1]

    scanner = Drheader(url=target_url, **kwargs)
    rules = utils.get_rules(rules_file=rules_file, rules_uri=rules_uri, merge_default=merge)
    report = scanner.analyze(rules=rules, cross_origin_isolated=cross_origin_isolated)

    if output == 'json':
        click.echo(json.dumps(report, indent=4))
    else:
        click.echo()
        if not report:
            click.echo('No issues found!')
        else:
            click.echo(f"{target_url}: {len(report)} issues found")
            click.echo(utils.tabulate_report(report))
    if junit:
        utils.file_junit_report(rules, report)

    sys.exit(os.EX_SOFTWARE if report else os.EX_OK)


@scan.command(context_settings={
    'default_map': {
        'file_format': 'json',
        'output': 'table'
    }
})
@click.argument('file', type=File(), required=True)
@click.option('--cross-origin-isolated', '-co', is_flag=True, help='Enable cross-origin isolation validations')
@click.option('--debug', '-d', is_flag=True, help='Enable debug logging')
@click.option('--file-format', '-ff', type=Choice(['json', 'txt'], case_sensitive=False), help='FILE input format')
@click.option('--merge', '-m', is_flag=True, help='Merge a custom ruleset with the default rules')
@click.option('--output', '-o', type=Choice(_OUTPUT_TYPES, case_sensitive=False), help='Report output format')
@click.option('--rules-file', '-rf', type=File(), help='Use a custom ruleset, loaded from file')
@click.option('--rules-uri', '-ru', metavar='URI', help='Use a custom ruleset, downloaded from URI')
def bulk(file, cross_origin_isolated, debug, file_format, merge, output, rules_file, rules_uri):  # noqa: F811
    if debug:
        logging.basicConfig(level=logging.DEBUG)

    if file_format == 'txt':
        urls = [{'url': url} for url in list(filter(None, file.read().splitlines()))]
    else:
        urls = json.loads(file.read())
        with open(os.path.join(os.path.dirname(__file__), '../resources/cli/bulk_scan_schema.json')) as schema:
            schema = json.load(schema)
            jsonschema.validate(instance=urls, schema=schema)

    audit = []
    rules = utils.get_rules(rules_file=rules_file, rules_uri=rules_uri, merge_default=merge)
    for target in urls:
        for key, value in target.items():
            try:
                target[key] = ast.literal_eval(value)  # This handles bytes and tuples
            except (SyntaxError, ValueError):
                target[key] = value

        try:
            scanner = Drheader(**target)
            report = scanner.analyze(rules=rules, cross_origin_isolated=cross_origin_isolated)
            audit.append({'url': target['url'], 'report': report})
        except Exception as e:
            audit.append({'url': target['url'], 'report': [], 'error': str(e)})

    if output == 'json':
        click.echo(json.dumps(audit, indent=4))
    else:
        for target in audit:
            click.echo()
            if target.get('error'):
                click.echo(f"{target['url']}: {target['error']}")
            elif not target['report']:
                click.echo(f"{target['url']}: No issues found!")
            else:
                click.echo(f"{target['url']}: {len(target['report'])} issues found")
                click.echo(utils.tabulate_report(target['report']))

    for target in audit:
        if target.get('report') or target.get('error'):
            sys.exit(os.EX_SOFTWARE)
    else:
        sys.exit(os.EX_OK)


def start():
    try:
        main()
    except Exception as e:
        click.secho(str(e), fg='red')


if __name__ == '__main__':
    start()
