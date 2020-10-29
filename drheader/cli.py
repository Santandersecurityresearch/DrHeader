# -*- coding: utf-8 -*-

"""Console script for drheader."""

import json
import logging

import click
import jsonschema
import sys
import os
import validators
from tabulate import tabulate

from drheader import Drheader
from drheader import __version__
from drheader.cli_utils import echo_bulk_report, file_junit_report
from drheader.utils import load_rules, get_rules_from_uri


EXIT_CODE_NO_ERROR = os.EX_OK
EXIT_CODE_FAILURE = os.EX_SOFTWARE


def print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.echo(__version__)
    ctx.exit()


@click.group()
@click.option('--version', '-v', is_flag=True, callback=print_version, expose_value=False, is_eager=True)
def main():
    """Console script for drheader."""


@main.group()
@click.option('--verify', '--verify-enable', default=True, help='Bool indicating SSL verification')
@click.option('--certs', '--certificates', help='Path to certificate bundle')
@click.pass_context
def scan(ctx, verify, certs):
    """Scan endpoints with drheader."""
    ctx.ensure_object(dict)
    if certs:
        verify = certs
    else:
        verify = click.BOOL(verify)
    ctx.obj['verify'] = verify


@main.command()
@click.argument('file', type=click.File(), required=True)
@click.option('--json', 'json_output', help='Output report as json', is_flag=True)
@click.option('--debug', help='Show error messages', is_flag=True)
@click.option('--rules', 'rule_file', help='Use custom rule set', type=click.File())
@click.option('--rules-uri', 'rule_uri', help='Use custom rule set, downloaded from URI')
@click.option('--merge', help='Merge custom file rules, on top of default rules', is_flag=True)
def compare(file, json_output, debug, rule_file, rule_uri, merge):
    """
    If you have headers you would like to test with drheader, you can "compare" them with your ruleset this command.

    This command requires a valid json file as input.

    Example:

        \b
        [
            {
                "url": "https://test.com",
                "headers": {
                    "X-XSS-Protection": "1; mode=block",
                    "Content-Security-Policy": "default-src 'none'; script-src 'self' unsafe-inline; object-src 'self';"
                    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                    "X-Frame-Options": "SAMEORIGIN",
                    "X-Content-Type-Options": "nosniff",
                    "Referrer-Policy": "strict-origin",
                    "Cache-Control": "no-cache, no-store, must-revalidate",
                    "Pragma": "no-cache",
                    "Set-Cookie": ["HttpOnly; Secure"]
                },
                "status_code": 200
            },
            ...
        ]
    """
    exit_code = EXIT_CODE_NO_ERROR
    audit = []
    schema = {
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    'format': 'uri'
                },
                "headers": {
                    "type": "object"
                },
                "status_code": {"type": "integer"}
            },
            "required": ['headers', 'url']
        }
    }

    if debug:
        logging.basicConfig(level=logging.DEBUG)

    try:
        data = json.loads(file.read())
        jsonschema.validate(instance=data, schema=schema, format_checker=jsonschema.FormatChecker())
        logging.debug('Found {} URLs'.format(len(data)))
    except Exception as e:
        raise click.ClickException(e)

    if rule_uri and not rule_file:
        if not validators.url(rule_uri):
            raise click.ClickException(message='"{}" is not a valid URL.'.format(rule_uri))
        try:
            rule_file = get_rules_from_uri(rule_uri)
        except Exception as e:
            if debug:
                raise click.ClickException(e)
            else:
                raise click.ClickException('No content retrieved from rules-uri.')

    rules = load_rules(rule_file, merge)

    for i in data:
        logging.debug('Analysing : {}'.format(i['url']))
        drheader_instance = Drheader(url=i['url'], headers=i['headers'])
        drheader_instance.analyze(rules)
        audit.append({'url': i['url'], 'report': drheader_instance.report})
        if drheader_instance.report:
            exit_code = EXIT_CODE_FAILURE

    echo_bulk_report(audit, json_output)
    sys.exit(exit_code)


@scan.command()
@click.argument('target_url', required=True)
@click.option('--json', 'json_output', help='Output report as json', is_flag=True)
@click.option('--debug', help='Show error messages', is_flag=True)
@click.option('--rules', 'rule_file', help='Use custom rule set', type=click.File())
@click.option('--rules-uri', 'rule_uri', help='Use custom rule set, downloaded from URI')
@click.option('--merge', help='Merge custom file rules, on top of default rules', is_flag=True)
@click.option('--junit', help='Produces a junit report with the result of the scan', is_flag=True)
@click.pass_context
def single(ctx, target_url, json_output, debug, rule_file, rule_uri, merge, junit):
    """
    Scan a single http(s) endpoint with drheader.

    NOTE: URL parameters are currently only supported on bulk scans.
    """
    exit_code = EXIT_CODE_NO_ERROR
    if debug:
        logging.basicConfig(level=logging.DEBUG)

    logging.debug('Validating: {}'.format(target_url))
    if not validators.url(target_url):
        raise click.ClickException(message='"{}" is not a valid URL.'.format(target_url))

    if rule_uri and not rule_file:
        if not validators.url(rule_uri):
            raise click.ClickException(message='"{}" is not a valid URL.'.format(rule_uri))
        try:
            rule_file = get_rules_from_uri(rule_uri)
        except Exception as e:
            if debug:
                raise click.ClickException(e)
            else:
                raise click.ClickException('No content retrieved from rules-uri.')

    rules = load_rules(rule_file, merge)

    try:
        logging.debug('Querying headers...')
        drheader_instance = Drheader(url=target_url, verify=ctx.obj['verify'])
    except Exception as e:
        if debug:
            raise click.ClickException(e)
        else:
            raise click.ClickException('Failed to get headers.')

    try:
        logging.debug('Analyzing headers...')
        drheader_instance.analyze(rules)
    except Exception as e:
        if debug:
            raise click.ClickException(e)
        else:
            raise click.ClickException('Failed to analyze headers.')

    if drheader_instance.report:
        exit_code = EXIT_CODE_FAILURE

    if json_output:
        click.echo(json.dumps(drheader_instance.report))
    else:
        click.echo()
        if not drheader_instance.report:
            click.echo('No issues found!')
        else:
            click.echo('{0} issues found'.format(len(drheader_instance.report)))
            for i in drheader_instance.report:
                values = []
                for k, v in i.items():
                    values.append([k, v])
                click.echo('----')
                click.echo(tabulate(values, tablefmt="presto"))
    if junit:
        file_junit_report(rules, drheader_instance.report)
    sys.exit(exit_code)


@scan.command()
@click.argument('file', type=click.File(), required=True)
@click.option('--file-format', '-ff', 'input_format', type=click.Choice(['json', 'txt']),
              help='bulk file input type. (defaults to json)')
@click.option('--post', '-p', help='Use a post request to obtain headers', is_flag=True)
@click.option('--json', 'json_output', help='Output report as json', is_flag=True)
@click.option('--debug', help='Show error messages', is_flag=True)
@click.option('--rules', 'rule_file', help='Use custom rule set', type=click.File())
@click.option('--rules-uri', 'rule_uri', help='Use custom rule set, downloaded from URI')
@click.option('--merge', help='Merge custom file rules, on top of default rules', is_flag=True)
@click.pass_context
def bulk(ctx, file, json_output, post, input_format, debug, rule_file, rule_uri, merge):
    """
    Scan multiple http(s) endpoints with drheader.

    The default file format is json:

        \b
        [
          {
            "url": "https://example.com",
            "params": {
                "example_parameter_key": "example_parameter_value"
            }
          },
          ...
        ]

    You can also use a txt file for input (using the "-ff txt" option):

        \b
        https://example.com
        https://example.co.uk

    NOTE: URL parameters are currently only supported on bulk scans.
    """
    exit_code = EXIT_CODE_NO_ERROR
    audit = []
    urls = []
    schema = {
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    'format': 'uri'
                },
                "params": {
                    "type": "string"
                },
            },
            "required": ['url']
        }
    }

    if debug:
        logging.basicConfig(level=logging.DEBUG)

    if input_format == 'txt':
        urls_temp = list(filter(None, file.read().splitlines()))
        for i in urls_temp:
            urls.append({'url': i})
        for i, v in enumerate(urls):
            logging.debug('Found: {}'.format(v))
            if not validators.url(v['url']):
                raise click.ClickException(message='[line {}] "{}" is not a valid URL.'.format(i + 1, v['url']))
    else:
        try:
            urls = json.loads(file.read())
            jsonschema.validate(instance=urls, schema=schema, format_checker=jsonschema.FormatChecker())
        except Exception as e:
            raise click.ClickException(e)

    logging.debug('Found {} URLs'.format(len(urls)))

    if rule_uri and not rule_file:
        if not validators.url(rule_uri):
            raise click.ClickException(message='"{}" is not a valid URL.'.format(rule_uri))
        try:
            rule_file = get_rules_from_uri(rule_uri)
        except Exception as e:
            if debug:
                raise click.ClickException(e)
            else:
                raise click.ClickException('No content retrieved from rules-uri.')

    rules = load_rules(rule_file, merge)

    for i, v in enumerate(urls):
        logging.debug('Querying: {}...'.format(v))
        drheader_instance = Drheader(
            url=v['url'], post=post, params=v.get('params', None), verify=ctx.obj['verify'])
        logging.debug('Analysing: {}...'.format(v))
        drheader_instance.analyze(rules)
        audit.append({'url': v['url'], 'report': drheader_instance.report})
        if drheader_instance.report:
            exit_code = EXIT_CODE_FAILURE

    echo_bulk_report(audit, json_output)
    sys.exit(exit_code)


if __name__ == "__main__":
    sys.exit(main())  # pragma: no cover
