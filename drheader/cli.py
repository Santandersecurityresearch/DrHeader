"""Console script for drheader."""

import json
import os
import sys

import click
import jsonschema
import validators
from click import ClickException, ParamType
from jsonschema import FormatChecker

from drheader import cli_utils, Drheader, __version__


class URLParamType(ParamType):

    name = 'URL'

    def convert(self, value, param, ctx):
        if not value.startswith('http'):
            scheme = click.prompt('Please select a scheme', type=click.Choice(['http', 'https']))
            value = f'{scheme}://{value}'
        if not validators.url(value):
            self.fail(f"'{value}' is not a valid URL")
        return value


@click.group()
@click.version_option(__version__, '--version', '-v')
def main():
    """Console script for drheader."""


@main.group()
@click.option('--no-verify', is_flag=True, help='Disable SSL verification')
@click.option('--certs', type=click.Path(), help='Certificate bundle for SSL verification')
@click.pass_context
def scan(ctx, no_verify, certs):
    """Scan endpoints with drheader."""
    ctx.ensure_object(dict)
    ctx.obj['verify'] = certs if certs else not no_verify


@main.group()
def compare():
    """Compare headers with drheader."""


@compare.command()
@click.argument('file', type=click.File(), required=True)
@click.option('--cross-origin-isolated', is_flag=True, help='Enable cross-origin isolation validations')
@click.option('--debug', is_flag=True, help='Enable debug logging')
@click.option('--junit', is_flag=True, help='Generate a JUnit report with the result of the scan')
@click.option('--merge', is_flag=True, help='Merge a custom ruleset with the default rules')
@click.option('--output', type=click.Choice(['json', 'table']), help='Report output format (default is table)')
@click.option('--rules-file', type=click.File(), help='Use a custom ruleset, loaded from file')
@click.option('--rules-uri', type=str, help='Use a custom ruleset, downloaded from URI')
def single(file, cross_origin_isolated, debug, junit, merge, output, rules_file, rules_uri):
    scanner = Drheader(headers=json.loads(file.read()))
    rules = cli_utils.get_rules(rules_file=rules_file, rules_uri=rules_uri, merge_default=merge)
    report = scanner.analyze(rules=rules, cross_origin_isolated=cross_origin_isolated)

    if output == 'json':
        click.echo(json.dumps(report, indent=4))
    else:
        click.echo()
        if not report:
            click.echo('No issues found!')
        else:
            click.echo(f'{len(report)} issues found')
            click.echo(cli_utils.tabulate_report(report))
    if junit:
        cli_utils.file_junit_report(rules, report)

    sys.exit(os.EX_SOFTWARE if report else os.EX_OK)


@compare.command()
@click.argument('file', type=click.File(), required=True)
@click.option('--cross-origin-isolated', is_flag=True, help='Enable cross-origin isolation validations')
@click.option('--debug', is_flag=True, help='Enable debug logging')
@click.option('--merge', is_flag=True, help='Merge a custom ruleset with the default rules')
@click.option('--output', type=click.Choice(['json', 'table']), help='Report output format (default is table)')
@click.option('--rules-file', type=click.File(), help='Use a custom ruleset, loaded from file')
@click.option('--rules-uri', type=str, help='Use a custom ruleset, downloaded from URI')
def bulk(file, cross_origin_isolated, debug, merge, output, rules_file, rules_uri):
    data = json.loads(file.read())
    with open(os.path.join(os.path.dirname(__file__), 'resources/bulk_compare_schema.json')) as schema:
        schema = json.load(schema)
        jsonschema.validate(instance=data, schema=schema, format_checker=FormatChecker())

    audit = []
    rules = cli_utils.get_rules(rules_file=rules_file, rules_uri=rules_uri, merge_default=merge)
    for target in data:
        scanner = Drheader(headers=target['headers'])
        report = scanner.analyze(rules=rules, cross_origin_isolated=cross_origin_isolated)
        audit.append({'url': target['url'], 'report': report})

    if output == 'json':
        click.echo(json.dumps(audit, indent=4))
    else:
        for target in audit:
            click.echo()
            if not target['report']:
                click.echo(f"{target['url']}: No issues found!")
            else:
                click.echo(f"{target['url']}: {len(target['report'])} issues found")
                click.echo(cli_utils.tabulate_report(target['report']))

    sys.exit(os.EX_SOFTWARE if any(target['report'] for target in audit) else os.EX_OK)


@scan.command()
@click.argument('target_url', type=URLParamType(), required=True)
@click.option('--cross-origin-isolated', is_flag=True, help='Enable cross-origin isolation validations')
@click.option('--debug', is_flag=True, help='Enable debug logging')
@click.option('--junit', is_flag=True, help='Generate a JUnit report with the result of the scan')
@click.option('--merge', is_flag=True, help='Merge a custom ruleset with the default rules')
@click.option('--output', type=click.Choice(['json', 'table']), help='Report output format (default is table)')
@click.option('--rules-file', type=click.File(), help='Use a custom ruleset, loaded from file')
@click.option('--rules-uri', type=str, help='Use a custom ruleset, downloaded from URI')
@click.pass_context
def single(ctx, target_url, cross_origin_isolated, debug, junit, merge, output, rules_file, rules_uri):  # noqa: F811
    scanner = Drheader(url=target_url, verify=ctx.obj['verify'])
    rules = cli_utils.get_rules(rules_file=rules_file, rules_uri=rules_uri, merge_default=merge)
    report = scanner.analyze(rules=rules, cross_origin_isolated=cross_origin_isolated)

    if output == 'json':
        click.echo(json.dumps(report, indent=4))
    else:
        click.echo()
        if not report:
            click.echo('No issues found!')
        else:
            click.echo(f"{target_url}: {len(report)} issues found")
            click.echo(cli_utils.tabulate_report(report))
    if junit:
        cli_utils.file_junit_report(rules, report)

    sys.exit(os.EX_SOFTWARE if report else os.EX_OK)


@scan.command()
@click.argument('file', type=click.File(), required=True)
@click.option('--cross-origin-isolated', is_flag=True, help='Enable cross-origin isolation validations')
@click.option('--debug', is_flag=True, help='Enable debug logging')
@click.option('--file-format', '-ff', type=click.Choice(['json', 'txt']), help='FILE input format (default is JSON)')
@click.option('--merge', is_flag=True, help='Merge a custom ruleset with the default rules')
@click.option('--output', type=click.Choice(['json', 'table']), help='Report output format (default is table)')
@click.option('--rules-file', type=click.File(), help='Use a custom ruleset, loaded from file')
@click.option('--rules-uri', type=str, help='Use a custom ruleset, downloaded from URI')
@click.pass_context
def bulk(ctx, file, cross_origin_isolated, debug, file_format, merge, output, rules_file, rules_uri):  # noqa: F811
    if file_format == 'txt':
        urls = []
        for url in list(filter(None, file.read().splitlines())):
            if not validators.url(url):
                raise ClickException(message=f"'{url}' is not a valid URL")
            urls.append({'url': url})
    else:
        urls = json.loads(file.read())
        with open(os.path.join(os.path.dirname(__file__), 'resources/bulk_scan_schema.json')) as schema:
            schema = json.load(schema)
            jsonschema.validate(instance=urls, schema=schema, format_checker=FormatChecker())

    audit = []
    rules = cli_utils.get_rules(rules_file=rules_file, rules_uri=rules_uri, merge_default=merge)
    for target in urls:
        scanner = Drheader(url=target['url'], params=target.get('params'), verify=ctx.obj['verify'])
        report = scanner.analyze(rules=rules, cross_origin_isolated=cross_origin_isolated)
        audit.append({'url': target['url'], 'report': report})

    if output == 'json':
        click.echo(json.dumps(audit, indent=4))
    else:
        for target in audit:
            click.echo()
            if not target['report']:
                click.echo(f"{target['url']}: No issues found!")
            else:
                click.echo(f"{target['url']}: {len(target['report'])} issues found")
                click.echo(cli_utils.tabulate_report(target['report']))

    sys.exit(os.EX_SOFTWARE if any(target['report'] for target in audit) else os.EX_OK)


if __name__ == "__main__":
    sys.exit(main())
