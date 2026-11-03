import unittest

from app import app


class AuthenticationFlowTests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True, SECRET_KEY="test-secret")
        self.client = app.test_client()
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)

    def _token_from_home(self):
        with self.client.session_transaction() as browser_session:
            return browser_session["csrf_token"]

    def _start(self, consent="yes"):
        return self.client.post(
            "/auth/start",
            data={"csrf_token": self._token_from_home(), "consent": consent},
            follow_redirects=False,
        )

    def test_requires_consent(self):
        response = self._start(consent="no")
        self.assertEqual(response.status_code, 400)

    def test_requires_csrf_token(self):
        response = self.client.post("/auth/start", data={"consent": "yes"})
        self.assertEqual(response.status_code, 400)

    def test_mock_verification_is_one_time_and_explicitly_not_authentication(self):
        start = self._start()
        self.assertEqual(start.status_code, 302)
        provider_page = self.client.get(start.headers["Location"])
        self.assertEqual(provider_page.status_code, 200)
        self.assertIn(b"000000000000", provider_page.data)
        self.assertIn(b'pattern="[0-9]{12}"', provider_page.data)
        self.assertIn(b'maxlength="12"', provider_page.data)
        self.assertIn(b"never sent to the server", provider_page.data)
        self.assertIn(b"Simulated success only", provider_page.data)
        self.assertNotIn(b'name="aadhaar"', provider_page.data.lower())

        with self.client.session_transaction() as browser_session:
            attempt_id = browser_session["attempt_id"]

        result = self.client.post(
            "/mock-provider/complete",
            data={
                "csrf_token": self._token_from_home(),
                "attempt_id": attempt_id,
                "outcome": "verified",
            },
        )
        self.assertEqual(result.status_code, 302)
        home = self.client.get("/")
        self.assertIn(b"this is not authentication", home.data)
        self.assertIn(b"SHA-256 hash matches", home.data)
        self.assertIn(b"UIDAI response signature verified", home.data)

        replay = self.client.post(
            "/mock-provider/complete",
            data={
                "csrf_token": self._token_from_home(),
                "attempt_id": attempt_id,
                "outcome": "verified",
            },
        )
        self.assertEqual(replay.status_code, 410)

    def test_provider_page_posts_to_server_when_test_value_matches(self):
        start = self._start()
        provider_page = self.client.get(start.headers["Location"])
        self.assertIn(b'id="complete-form"', provider_page.data)
        self.assertIn(b'name="outcome" value="verified"', provider_page.data)

    def test_rejects_unexpected_outcome(self):
        start = self._start()
        with self.client.session_transaction() as browser_session:
            attempt_id = browser_session["attempt_id"]
        response = self.client.post(
            "/mock-provider/complete",
            data={
                "csrf_token": self._token_from_home(),
                "attempt_id": attempt_id,
                "outcome": "anything",
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(start.status_code, 302)


if __name__ == "__main__":
    unittest.main()
