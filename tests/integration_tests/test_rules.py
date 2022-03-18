from tests.integration_tests.test_base import TestBase


class TestDefaultRules(TestBase):

    def test_compare_rules_ok(self):
        headers = super().get_headers()

        report = super().process_test(headers=headers)
        self.assertEqual(len(report), 0, msg=super().build_error_message(report))

    def test_cache_control_not_present_ko(self):
        headers = super().delete_header('Cache-Control')

        report = super().process_test(headers=headers)
        expected = {
            'rule': 'Cache-Control',
            'severity': 'high',
            'message': 'Header not included in response',
            'expected': ['no-store', 'max-age=0'],
            'delimiter': ','
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'Cache-Control'))

    def test_cache_control_allow_caching_ko(self):
        headers = super().add_or_modify_header('Cache-Control', 'no-cache')

        report = super().process_test(headers=headers)
        expected = {
            'rule': 'Cache-Control',
            'severity': 'high',
            'message': 'Value does not match security policy. All of the expected items were expected',
            'expected': ['no-store', 'max-age=0'],
            'delimiter': ',',
            'value': 'no-cache'
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'Cache-Control'))

    def test_csp_not_present_ko(self):
        headers = super().delete_header('Content-Security-Policy')

        report = super().process_test(headers=headers)
        expected = {
            'rule': 'Content-Security-Policy',
            'severity': 'high',
            'message': 'Header not included in response'
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'Content-Security-Policy'))

    def test_csp_default_src_ko(self):
        headers = super().add_or_modify_header('Content-Security-Policy', 'default-src https://example.com')

        report = super().process_test(headers=headers)
        expected = {
            'rule': 'Content-Security-Policy - default-src',
            'severity': 'high',
            'message': 'Value does not match security policy. Exactly one of the expected items was expected',
            'expected': ['none', 'self'],
            'value': 'https://example.com'
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'Content-Security-Policy'))

    def test_pragma_not_present_ko(self):
        headers = super().delete_header('Pragma')

        report = super().process_test(headers=headers)
        expected = {
            'rule': 'Pragma',
            'severity': 'high',
            'message': 'Header not included in response',
            'expected': ['no-cache']
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'Pragma'))

    def test_referrer_policy_not_present_ko(self):
        headers = super().delete_header('Referrer-Policy')

        report = super().process_test(headers=headers)
        expected = {
            'rule': 'Referrer-Policy',
            'severity': 'high',
            'message': 'Header not included in response',
            'expected': ['strict-origin', 'strict-origin-when-cross-origin', 'no-referrer'],
            'delimiter': ','
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'Referrer-Policy'))

    def test_referrer_policy_not_strict_ko(self):
        headers = super().add_or_modify_header('Referrer-Policy', 'same-origin')

        report = super().process_test(headers=headers)
        expected = {
            'rule': 'Referrer-Policy',
            'severity': 'high',
            'message': 'Value does not match security policy. At least one of the expected items was expected',
            'expected': ['strict-origin', 'strict-origin-when-cross-origin', 'no-referrer'],
            'value': 'same-origin',
            'anomalies': ['same-origin'],
            'delimiter': ','
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'Referrer-Policy'))

    def test_server_ko(self):
        headers = super().add_or_modify_header('Server', 'Apache/2.4.1 (Unix)')

        report = super().process_test(headers=headers)
        expected = {
            'severity': 'high',
            'rule': 'Server',
            'message': 'Header should not be returned'
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'Server'))

    def test_set_cookie_not_secure_ko(self):
        headers = super().add_or_modify_header('Set-Cookie', ['session_id=585733723; HttpOnly; SameSite=Strict'])

        report = super().process_test(headers=headers)
        expected = {
            'rule': 'Set-Cookie',
            'severity': 'medium',
            'message': 'Must-Contain directive missed. All of the expected items were expected',
            'expected': ['HttpOnly', 'Secure'],
            'value': 'session_id=585733723; HttpOnly; SameSite=Strict',
            'anomalies': ['Secure'],
            'delimiter': ';'
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'Set-Cookie'))

    def test_set_cookie_not_httponly_ko(self):
        headers = super().add_or_modify_header('Set-Cookie', ['session_id=585733723; Secure; SameSite=Strict'])

        report = super().process_test(headers=headers)
        expected = {
            'rule': 'Set-Cookie',
            'severity': 'medium',
            'message': 'Must-Contain directive missed. All of the expected items were expected',
            'expected': ['HttpOnly', 'Secure'],
            'value': 'session_id=585733723; Secure; SameSite=Strict',
            'anomalies': ['HttpOnly'],
            'delimiter': ';',
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'Set-Cookie'))

    def test_strict_transport_security_not_present_ko(self):
        headers = super().delete_header('Strict-Transport-Security')

        report = super().process_test(headers=headers)
        expected = {
            'rule': 'Strict-Transport-Security',
            'severity': 'high',
            'message': 'Header not included in response',
            'expected': ['max-age=31536000', 'includeSubDomains'],
            'delimiter': ';'
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'Strict-Transport-Security'))

    def test_user_agent_ko(self):
        headers = super().add_or_modify_header('User-Agent', 'Dalvik/2.1.0 (Linux; U; Android 6.0.1; Nexus Player)')

        report = super().process_test(headers=headers)
        expected = {
            'severity': 'high',
            'rule': 'User-Agent',
            'message': 'Header should not be returned'
        }
        self.assertIn(expected, report, msg=self.build_error_message(report, expected, 'User-Agent'))

    def test_x_aspnet_version_ko(self):
        headers = super().add_or_modify_header('X-AspNet-Version', '2.0.50727')

        report = super().process_test(headers=headers)
        expected = {
            'severity': 'high',
            'rule': 'X-AspNet-Version',
            'message': 'Header should not be returned'
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'X-AspNet-Version'))

    def test_x_client_ip_ko(self):
        headers = super().add_or_modify_header('X-Client-IP', '27.59.32.182')

        report = super().process_test(headers=headers)
        expected = {
            'severity': 'high',
            'rule': 'X-Client-IP',
            'message': 'Header should not be returned'
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'X-Client-IP'))

    def test_x_content_type_options_not_present_ko(self):
        headers = super().delete_header('X-Content-Type-Options')

        report = super().process_test(headers=headers)
        expected = {
            'rule': 'X-Content-Type-Options',
            'severity': 'high',
            'message': 'Header not included in response',
            'expected': ['nosniff']
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'X-Content-Type-Options'))

    def test_x_frame_options_not_present_ko(self):
        headers = super().delete_header('X-Frame-Options')

        report = super().process_test(headers=headers)
        expected = {
            'rule': 'X-Frame-Options',
            'severity': 'high',
            'message': 'Header not included in response',
            'expected': ['DENY', 'SAMEORIGIN']
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'X-Frame-Options'))

    def test_x_frame_options_allow_from_ko(self):
        headers = super().add_or_modify_header('X-Frame-Options', 'ALLOW-FROM https//example.com')

        report = super().process_test(headers=headers)
        expected = {
            'rule': 'X-Frame-Options',
            'severity': 'high',
            'message': 'Value does not match security policy. Exactly one of the expected items was expected',
            'expected': ['DENY', 'SAMEORIGIN'],
            'value': 'ALLOW-FROM https//example.com'
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'X-Frame-Options'))

    def test_x_forwarded_for_ko(self):
        headers = super().add_or_modify_header('X-Forwarded-For', '2001:db8:85a3:8d3:1319:8a2e:370:7348')

        report = super().process_test(headers=headers)
        expected = {
            'severity': 'high',
            'rule': 'X-Forwarded-For',
            'message': 'Header should not be returned'
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'X-Forwarded-For'))

    def test_x_generator_ko(self):
        headers = super().add_or_modify_header('X-Generator', 'Drupal 7 (http://drupal.org)')

        report = super().process_test(headers=headers)
        expected = {
            'severity': 'high',
            'rule': 'X-Generator',
            'message': 'Header should not be returned'
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'X-Generator'))

    def test_x_powered_by_ko(self):
        headers = super().add_or_modify_header('X-Powered-By', 'ASP.NET')

        report = super().process_test(headers=headers)
        expected = {
            'severity': 'high',
            'rule': 'X-Powered-By',
            'message': 'Header should not be returned'
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'X-Powered-By'))

    def test_x_xss_protection_not_present_ko(self):
        headers = super().delete_header('X-XSS-Protection')

        report = super().process_test(headers=headers)
        expected = {
            'rule': 'X-XSS-Protection',
            'severity': 'high',
            'message': 'Header not included in response',
            'expected': ['0']
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'X-XSS-Protection'))

    def test_x_xss_protection_enable_filter_ko(self):
        headers = super().add_or_modify_header('X-XSS-Protection', '1; mode=block')

        report = super().process_test(headers=headers)
        expected = {
            'rule': 'X-XSS-Protection',
            'severity': 'high',
            'message': 'Value does not match security policy. All of the expected items were expected',
            'expected': ['0'],
            'value': '1; mode=block'
        }
        self.assertIn(expected, report, msg=super().build_error_message(report, expected, 'X-XSS-Protection'))
