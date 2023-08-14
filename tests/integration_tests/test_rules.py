import unittest

from tests.integration_tests import utils


class TestDefaultRules(unittest.TestCase):

    def tearDown(self):
        utils.reset_default_rules()

    def test__should_validate_all_rules_for_valid_headers(self):
        headers = utils.get_headers()

        report = utils.process_test(headers=headers)
        self.assertEqual(len(report), 0, msg=utils.build_error_message(report))

    def test_cache_control__should_exist(self):
        headers = utils.delete_headers('Cache-Control')

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'Cache-Control',
            'message': 'Header not included in response',
            'severity': 'high',
            'expected': ['no-store', 'max-age=0'],
            'delimiter': ','
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Cache-Control'))

    def test_cache_control__should_disable_caching(self):
        headers = utils.add_or_modify_header('Cache-Control', 'no-cache')

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'Cache-Control',
            'message': 'Value does not match security policy',
            'severity': 'high',
            'value': 'no-cache',
            'expected': ['no-store', 'max-age=0'],
            'delimiter': ','
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Cache-Control'))

    def test_csp__should_exist(self):
        headers = utils.delete_headers('Content-Security-Policy')

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'Content-Security-Policy',
            'message': 'Header not included in response',
            'severity': 'high'
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Content-Security-Policy'))

    def test_csp__should_enforce_default_src(self):
        headers = utils.add_or_modify_header('Content-Security-Policy', 'default-src https://example.com')

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'Content-Security-Policy - default-src',
            'message': 'Value does not match security policy. Exactly one of the expected items was expected',
            'severity': 'high',
            'value': 'https://example.com',
            'expected': ['none', 'self']
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Content-Security-Policy'))

    def test_coep__should_exist_when_cross_origin_isolated_is_true(self):
        headers = utils.delete_headers('Cross-Origin-Embedder-Policy')

        report = utils.process_test(headers=headers, cross_origin_isolated=True)
        expected = {
            'rule': 'Cross-Origin-Embedder-Policy',
            'message': 'Header not included in response',
            'severity': 'high',
            'expected': ['require-corp']
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Cross-Origin-Embedder-Policy'))

    def test_coep__should_enforce_require_corp_when_cross_origin_isolated_is_true(self):
        headers = utils.add_or_modify_header('Cross-Origin-Embedder-Policy', 'unsafe-none')

        report = utils.process_test(headers=headers, cross_origin_isolated=True)
        expected = {
            'rule': 'Cross-Origin-Embedder-Policy',
            'message': 'Value does not match security policy',
            'severity': 'high',
            'value': 'unsafe-none',
            'expected': ['require-corp']
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Cross-Origin-Embedder-Policy'))

    def test_coop__should_exist_when_cross_origin_isolated_is_true(self):
        headers = utils.delete_headers('Cross-Origin-Opener-Policy')

        report = utils.process_test(headers=headers, cross_origin_isolated=True)
        expected = {
            'rule': 'Cross-Origin-Opener-Policy',
            'message': 'Header not included in response',
            'severity': 'high',
            'expected': ['same-origin']
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Cross-Origin-Opener-Policy'))

    def test_coop__should_enforce_same_origin_when_cross_origin_isolated_is_true(self):
        headers = utils.add_or_modify_header('Cross-Origin-Opener-Policy', 'same-origin-allow-popups')

        report = utils.process_test(headers=headers, cross_origin_isolated=True)
        expected = {
            'rule': 'Cross-Origin-Opener-Policy',
            'message': 'Value does not match security policy',
            'severity': 'high',
            'value': 'same-origin-allow-popups',
            'expected': ['same-origin']
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Cross-Origin-Opener-Policy'))

    def test_pragma__should_exist(self):
        headers = utils.delete_headers('Pragma')

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'Pragma',
            'message': 'Header not included in response',
            'severity': 'high',
            'expected': ['no-cache']
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Pragma'))

    def test_referrer_policy__should_exist(self):
        headers = utils.delete_headers('Referrer-Policy')

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'Referrer-Policy',
            'message': 'Header not included in response',
            'severity': 'high',
            'expected': ['strict-origin', 'strict-origin-when-cross-origin', 'no-referrer']
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Referrer-Policy'))

    def test_referrer_policy__should_enforce_strict_policy(self):
        headers = utils.add_or_modify_header('Referrer-Policy', 'same-origin')

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'Referrer-Policy',
            'message': 'Value does not match security policy. Exactly one of the expected items was expected',
            'severity': 'high',
            'value': 'same-origin',
            'expected': ['strict-origin', 'strict-origin-when-cross-origin', 'no-referrer']
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Referrer-Policy'))

    def test_server__should_not_exist(self):
        headers = utils.add_or_modify_header('Server', 'Apache/2.4.1 (Unix)')

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'Server',
            'message': 'Header should not be returned',
            'severity': 'high'
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Server'))

    def test_set_cookie__should_enforce_secure_for_all_cookies(self):
        headers = utils.add_or_modify_header('Set-Cookie', ['session_id=585733723; HttpOnly; SameSite=Strict'])

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'Set-Cookie - session_id',
            'message': 'Must-Contain directive missed',
            'severity': 'high',
            'value': '585733723; HttpOnly; SameSite=Strict',
            'expected': ['HttpOnly', 'Secure'],
            'delimiter': ';',
            'anomalies': ['Secure']
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Set-Cookie'))

    def test_set_cookie__should_enforce_httponly_for_all_cookies(self):
        headers = utils.add_or_modify_header('Set-Cookie', ['session_id=585733723; Secure; SameSite=Strict'])

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'Set-Cookie - session_id',
            'message': 'Must-Contain directive missed',
            'severity': 'high',
            'value': '585733723; Secure; SameSite=Strict',
            'expected': ['HttpOnly', 'Secure'],
            'delimiter': ';',
            'anomalies': ['HttpOnly']
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Set-Cookie'))

    def test_strict_transport_security__should_exist(self):
        headers = utils.delete_headers('Strict-Transport-Security')

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'Strict-Transport-Security',
            'message': 'Header not included in response',
            'severity': 'high',
            'expected': ['max-age=31536000', 'includeSubDomains'],
            'delimiter': ';'
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'Strict-Transport-Security'))

    def test_user_agent__should_not_exist(self):
        headers = utils.add_or_modify_header('User-Agent', 'Dalvik/2.1.0 (Linux; U; Android 6.0.1; Nexus Player)')

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'User-Agent',
            'message': 'Header should not be returned',
            'severity': 'high'
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'User-Agent'))

    def test_x_aspnet_version__should_not_exist(self):
        headers = utils.add_or_modify_header('X-AspNet-Version', '2.0.50727')

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'X-AspNet-Version',
            'message': 'Header should not be returned',
            'severity': 'high'
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'X-AspNet-Version'))

    def test_x_client_ip__should_not_exist(self):
        headers = utils.add_or_modify_header('X-Client-IP', '27.59.32.182')

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'X-Client-IP',
            'message': 'Header should not be returned',
            'severity': 'high'
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'X-Client-IP'))

    def test_x_content_type_options__should_exist(self):
        headers = utils.delete_headers('X-Content-Type-Options')

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'X-Content-Type-Options',
            'message': 'Header not included in response',
            'severity': 'high',
            'expected': ['nosniff']
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'X-Content-Type-Options'))

    def test_x_frame_options__should_exist(self):
        headers = utils.delete_headers('X-Frame-Options')

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'X-Frame-Options',
            'message': 'Header not included in response',
            'severity': 'high',
            'expected': ['DENY', 'SAMEORIGIN']
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'X-Frame-Options'))

    def test_x_frame_options__should_disable_allow_from(self):
        headers = utils.add_or_modify_header('X-Frame-Options', 'ALLOW-FROM https//example.com')

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'X-Frame-Options',
            'message': 'Value does not match security policy. Exactly one of the expected items was expected',
            'severity': 'high',
            'value': 'ALLOW-FROM https//example.com',
            'expected': ['DENY', 'SAMEORIGIN']
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'X-Frame-Options'))

    def test_x_forwarded_for__should_not_exist(self):
        headers = utils.add_or_modify_header('X-Forwarded-For', '2001:db8:85a3:8d3:1319:8a2e:370:7348')

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'X-Forwarded-For',
            'message': 'Header should not be returned',
            'severity': 'high'
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'X-Forwarded-For'))

    def test_x_generator__should_not_exist(self):
        headers = utils.add_or_modify_header('X-Generator', 'Drupal 7 (http://drupal.org)')

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'X-Generator',
            'message': 'Header should not be returned',
            'severity': 'high'
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'X-Generator'))

    def test_x_powered_by__should_not_exist(self):
        headers = utils.add_or_modify_header('X-Powered-By', 'ASP.NET')

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'X-Powered-By',
            'message': 'Header should not be returned',
            'severity': 'high'
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'X-Powered-By'))

    def test_x_xss_protection__should_exist(self):
        headers = utils.delete_headers('X-XSS-Protection')

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'X-XSS-Protection',
            'message': 'Header not included in response',
            'severity': 'high',
            'expected': ['0']
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'X-XSS-Protection'))

    def test_x_xss_protection__should_disable_filter(self):
        headers = utils.add_or_modify_header('X-XSS-Protection', '1; mode=block')

        report = utils.process_test(headers=headers)
        expected = {
            'rule': 'X-XSS-Protection',
            'message': 'Value does not match security policy',
            'severity': 'high',
            'value': '1; mode=block',
            'expected': ['0']
        }
        self.assertIn(expected, report, msg=utils.build_error_message(report, expected, 'X-XSS-Protection'))
