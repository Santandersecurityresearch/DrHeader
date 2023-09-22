import json
import copy
import os
from unittest import TestCase

import responses
from click.testing import CliRunner
from responses import matchers

from drheader.cli import cli

_RESOURCES_DIR = os.path.join(os.path.dirname(__file__), '../test_resources')


# noinspection PyTypeChecker
class TestCli(TestCase):

    def setUp(self):
        responses.head('https://example.com')
        responses.head('https://example.net')
        responses.head('https://example.org')

        with open(os.path.join(_RESOURCES_DIR, 'bulk_scan.json')) as bulk_scan:
            self.bulk_scan = json.load(bulk_scan)
            self.bulk_scan_reset = copy.deepcopy(self.bulk_scan)

    def tearDown(self):
        with open(os.path.join(_RESOURCES_DIR, 'bulk_scan.json'), 'w') as bulk_scan:
            json.dump(self.bulk_scan_reset, bulk_scan, indent=4)

    @responses.activate
    def test_scan_single__should_process_request_method(self):
        mock = responses.post('https://example.com')
        CliRunner().invoke(cli.main,  ['scan', 'single', 'https://example.com', '--method', 'post'])

        assert mock.call_count == 1

    @responses.activate
    def test_scan_single__should_process_request_headers(self):
        headers = {'Authorization': 'Bearer YWxh2GGVuc2VzYW1l'}
        mock = responses.upsert(responses.HEAD, 'https://example.com', match=[matchers.header_matcher(headers)])

        CliRunner().invoke(cli.main,  ['scan', 'single', 'https://example.com', '--headers', json.dumps(headers)])

        assert mock.call_count == 1

    @responses.activate
    def test_scan_single__should_process_request_params(self):
        params = {'username': 'h_simpson', 'password': 'doughnuts'}
        mock = responses.upsert(responses.HEAD, 'https://example.com', match=[matchers.query_param_matcher(params)])

        CliRunner().invoke(cli.main, ['scan', 'single', 'https://example.com', '--params', json.dumps(params)])

        assert mock.call_count == 1

    @responses.activate
    def test_scan_single__should_process_request_body(self):
        body = {'First Name': 'Homer', 'Last Name': 'Simpson'}
        mock = responses.upsert(responses.HEAD, 'https://example.com', match=[matchers.json_params_matcher(body)])

        CliRunner().invoke(cli.main, ['scan', 'single', 'https://example.com', '--json', json.dumps(body)])

        assert mock.call_count == 1

    @responses.activate
    def test_scan_single__should_process_no_verify(self):
        mock = responses.upsert(responses.HEAD, 'https://example.com', match=[matchers.request_kwargs_matcher({'verify': False})])
        CliRunner().invoke(cli.main, ['scan', 'single', 'https://example.com', '--verify', 'false'])

        assert mock.call_count == 1

    @responses.activate
    def test_scan_single__should_process_timeout(self):
        mock = responses.upsert(responses.HEAD, 'https://example.com', match=[matchers.request_kwargs_matcher({'timeout': 30})])
        CliRunner().invoke(cli.main, ['scan', 'single', 'https://example.com', '--timeout', '30'])

        assert mock.call_count == 1

    @responses.activate
    def test_scan_bulk__should_process_request_method(self):
        self._modify_bulk_scan('method', 'POST')
        mock = responses.post('https://example.com')

        file = os.path.join(_RESOURCES_DIR, 'bulk_scan.json')
        CliRunner().invoke(cli.main,  ['scan', 'bulk', file])

        assert mock.call_count == 1

    @responses.activate
    def test_scan_bulk__should_process_request_headers(self):
        self._modify_bulk_scan('headers', headers := {'Authorization': 'Bearer YWxh2GGVuc2VzYW1l'})
        mock = responses.upsert(responses.HEAD, 'https://example.com', match=[matchers.header_matcher(headers)])

        file = os.path.join(_RESOURCES_DIR, 'bulk_scan.json')
        CliRunner().invoke(cli.main,  ['scan', 'bulk', file])

        assert mock.call_count == 1

    @responses.activate
    def test_scan_bulk__should_process_request_params(self):
        self._modify_bulk_scan('params', params := {'username': 'h_simpson', 'password': 'doughnuts'})
        mock = responses.upsert(responses.HEAD, 'https://example.com', match=[matchers.query_param_matcher(params)])

        file = os.path.join(_RESOURCES_DIR, 'bulk_scan.json')
        CliRunner().invoke(cli.main,  ['scan', 'bulk', file])

        assert mock.call_count == 1

    @responses.activate
    def test_scan_bulk__should_process_request_body(self):
        self._modify_bulk_scan('json', body := {'First Name': 'Homer', 'Last Name': 'Simpson'})
        mock = responses.upsert(responses.HEAD, 'https://example.com', match=[matchers.json_params_matcher(body)])

        file = os.path.join(_RESOURCES_DIR, 'bulk_scan.json')
        CliRunner().invoke(cli.main,  ['scan', 'bulk', file])

        assert mock.call_count == 1

    @responses.activate
    def test_scan_bulk__should_process_no_verify(self):
        self._modify_bulk_scan('verify', False)
        mock = responses.upsert(responses.HEAD, 'https://example.com', match=[matchers.request_kwargs_matcher({'verify': False})])

        file = os.path.join(_RESOURCES_DIR, 'bulk_scan.json')
        CliRunner().invoke(cli.main,  ['scan', 'bulk', file])

        assert mock.call_count == 1

    @responses.activate
    def test_scan_bulk__should_process_timeout(self):
        self._modify_bulk_scan('timeout', 30)
        mock = responses.upsert(responses.HEAD, 'https://example.com', match=[matchers.request_kwargs_matcher({'timeout': 30})])

        file = os.path.join(_RESOURCES_DIR, 'bulk_scan.json')
        CliRunner().invoke(cli.main,  ['scan', 'bulk', file])

        assert mock.call_count == 1

    def _modify_bulk_scan(self, key, value):
        with open(os.path.join(_RESOURCES_DIR, 'bulk_scan.json'), 'w') as bulk_scan:
            self.bulk_scan[0][key] = value
            json.dump(self.bulk_scan, bulk_scan, indent=4)
