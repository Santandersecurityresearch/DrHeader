from tests.integration_tests.test_base import TestBase


class TestDefaultRules(TestBase):

    def test_compare_rules_ok(self):
        headers = TestBase.get_headers()

        self.process_test(headers=headers, status_code=200)
        self.assertEqual(len(self.instance.report), 0, msg=self.build_error_message(self.instance.report))

    def test_cache_control_not_present_ko(self):
        headers = self.modify_header('Cache-Control', None)
        expected_report_item = {
            'rule': 'Cache-Control',
            'severity': 'high',
            'message': 'Header not included in response',
            'expected': ['no-store', 'max-age=0'],
            'delimiter': ','
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='Cache-Control'))

    def test_cache_control_allow_caching_ko(self):
        headers = self.modify_header('Cache-Control', 'no-cache')
        expected_report_item = {
            'rule': 'Cache-Control',
            'severity': 'high',
            'message': 'Value does not match security policy',
            'expected': ['no-store', 'max-age=0'],
            'delimiter': ',',
            'value': 'no-cache'
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='Cache-Control'))

    def test_csp_not_present_ko(self):
        headers = self.modify_header('Content-Security-Policy', None)
        expected_report_item = {
            'rule': 'Content-Security-Policy',
            'severity': 'high',
            'message': 'Header not included in response'
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='Content-Security-Policy'))

    def test_csp_default_src_ko(self):
        headers = self.modify_header('Content-Security-Policy', "default-src 'https://www.santander.co.uk'")
        expected_report_item = {
            'rule': 'Content-Security-Policy',
            'severity': 'high',
            'message': 'Must-Contain-One directive missed',
            'expected': ["default-src 'none'", "default-src 'self'"],
            'delimiter': ';',
            'value': "default-src 'https://www.santander.co.uk'",
            'anomaly': ["default-src 'none'", "default-src 'self'"]
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='Content-Security-Policy'))

    def test_pragma_not_present_ko(self):
        headers = self.modify_header('Pragma', None)
        expected_report_item = {
            'rule': 'Pragma',
            'severity': 'high',
            'message': 'Header not included in response',
            'expected': ['no-cache'],
            'delimiter': ';'
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='Pragma'))

    def test_referrer_policy_not_present_ko(self):
        headers = self.modify_header('Referrer-Policy', None)
        expected_report_item = {
            'rule': 'Referrer-Policy',
            'severity': 'high',
            'message': 'Header not included in response'
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='Referrer-Policy'))

    def test_referrer_policy_not_strict_ko(self):
        headers = self.modify_header('Referrer-Policy', 'same-origin')
        expected_report_item = {
            'rule': 'Referrer-Policy',
            'severity': 'high',
            'message': 'Must-Contain-One directive missed',
            'expected': ['strict-origin', 'strict-origin-when-cross-origin', 'no-referrer'],
            'delimiter': ',',
            'value': 'same-origin',
            'anomaly': ['strict-origin', 'strict-origin-when-cross-origin', 'no-referrer']
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='Referrer-Policy'))

    def test_server_ko(self):
        headers = self.modify_header('Server', 'Apache/2.4.1 (Unix)')
        expected_report_item = {
            'severity': 'high',
            'rule': 'Server',
            'message': 'Header should not be returned'
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='Server'))

    def test_set_cookie_not_secure_ko(self):
        headers = self.modify_header('Set-Cookie', ['session_id=585733723; HttpOnly; SameSite=Strict'])
        expected_report_item = {
            'rule': 'Set-Cookie',
            'severity': 'high',
            'message': 'Must-Contain directive missed',
            'expected': ['httponly', 'secure'],
            'delimiter': ';',
            'value': 'session_id=585733723; httponly; samesite=strict',
            'anomaly': 'secure'
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='Set-Cookie'))

    def test_set_cookie_not_httponly_ko(self):
        headers = self.modify_header('Set-Cookie', ['session_id=585733723; Secure; SameSite=Strict'])
        expected_report_item = {
            'rule': 'Set-Cookie',
            'severity': 'medium',
            'message': 'Must-Contain directive missed',
            'expected': ['httponly', 'secure'],
            'delimiter': ';',
            'value': 'session_id=585733723; secure; samesite=strict',
            'anomaly': 'httponly'
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='Set-Cookie'))

    def test_strict_transport_security_not_present_ko(self):
        headers = self.modify_header('Strict-Transport-Security', None)
        expected_report_item = {
            'rule': 'Strict-Transport-Security',
            'severity': 'high',
            'message': 'Header not included in response',
            'expected': ['max-age=31536000', 'includesubdomains'],
            'delimiter': ';'
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='Strict-Transport-Security'))

    def test_user_agent_ko(self):
        headers = self.modify_header('User-Agent', 'Dalvik/2.1.0 (Linux; U; Android 6.0.1; Nexus Player Build/MMB29T)')
        expected_report_item = {
            'severity': 'high',
            'rule': 'User-Agent',
            'message': 'Header should not be returned'
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='User-Agent'))

    def test_x_aspnet_version_ko(self):
        headers = self.modify_header('X-AspNet-Version', '2.0.50727')
        expected_report_item = {
            'severity': 'high',
            'rule': 'X-AspNet-Version',
            'message': 'Header should not be returned'
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='X-AspNet-Version'))

    def test_x_client_ip_ko(self):
        headers = self.modify_header('X-Client-IP', '27.59.32.182')
        expected_report_item = {
            'severity': 'high',
            'rule': 'X-Client-IP',
            'message': 'Header should not be returned'
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='X-Client-IP'))

    def test_x_content_type_options_not_present_ko(self):
        headers = self.modify_header('X-Content-Type-Options', None)
        expected_report_item = {
            'rule': 'X-Content-Type-Options',
            'severity': 'high',
            'message': 'Header not included in response',
            'expected': ['nosniff'],
            'delimiter': ';'
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='X-Content-Type-Options'))

    def test_x_frame_options_not_present_ko(self):
        headers = self.modify_header('X-Frame-Options', None)
        expected_report_item = {
            'rule': 'X-Frame-Options',
            'severity': 'high',
            'message': 'Header not included in response',
            'expected': ['sameorigin', 'deny'],
            'delimiter': ';'
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='X-Frame-Options'))

    def test_x_frame_options_allow_from_ko(self):
        headers = self.modify_header('X-Frame-Options', 'ALLOW-FROM https//www.unsafe-url.com')
        expected_report_item = {
            'rule': 'X-Frame-Options',
            'severity': 'high',
            'message': 'Value does not match security policy',
            'expected': ['sameorigin', 'deny'],
            'delimiter': ';',
            'value': 'allow-from https//www.unsafe-url.com'
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='X-Frame-Options'))

    def test_x_forwarded_for_ko(self):
        headers = self.modify_header('X-Forwarded-For', '2001:db8:85a3:8d3:1319:8a2e:370:7348')
        expected_report_item = {
            'severity': 'high',
            'rule': 'X-Forwarded-For',
            'message': 'Header should not be returned'
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='X-Forwarded-For'))

    def test_x_generator_ko(self):
        headers = self.modify_header('X-Generator', 'Drupal 7 (http://drupal.org)')
        expected_report_item = {
            'severity': 'high',
            'rule': 'X-Generator',
            'message': 'Header should not be returned'
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='X-Generator'))

    def test_x_powered_by_ko(self):
        headers = self.modify_header('X-Powered-By', 'ASP.NET')
        expected_report_item = {
            'severity': 'high',
            'rule': 'X-Powered-By',
            'message': 'Header should not be returned'
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='X-Powered-By'))

    def test_x_xss_protection_not_present_ko(self):
        headers = self.modify_header('X-XSS-Protection', None)
        expected_report_item = {
            'rule': 'X-XSS-Protection',
            'severity': 'high',
            'message': 'Header not included in response',
            'expected': ['0'],
            'delimiter': ';'
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='X-XSS-Protection'))

    def test_x_xss_protection_enable_filter_ko(self):
        headers = self.modify_header('X-XSS-Protection', '1; mode=block')
        expected_report_item = {
            'rule': 'X-XSS-Protection',
            'severity': 'high',
            'message': 'Value does not match security policy',
            'expected': ['0'],
            'delimiter': ';',
            'value': '1; mode=block'
        }

        self.process_test(headers=headers, status_code=200)
        self.assertIn(expected_report_item, self.instance.report,
                      msg=self.build_error_message(self.instance.report, expected_report=[expected_report_item], rule='X-XSS-Protection'))
