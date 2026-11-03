"""Offline regression checks; no account credentials or network required."""
import contextlib
import io
import os
import unittest
from unittest.mock import Mock, patch

with patch.dict(os.environ, {}, clear=True):
    import ablesci
    import sendNotify


class CheckInRegression(unittest.TestCase):
    def test_account_delimiters_and_password_privacy(self):
        entries = [
            ("a@example.com:first,part;end;b@example.com|second",
             [("a@example.com", "first,part;end"), ("b@example.com", "second")]),
            ("a@example.com:has,other@example.com;tail\nb@example.com:p",
             [("a@example.com", "has,other@example.com;tail"), ("b@example.com", "p")]),
            ("a@example.com : punct,:;|;b@example.com:two",
             [("a@example.com", "punct,:;|"), ("b@example.com", "two")]),
            ("# ignored\ninvalid-private-password\na@example.com:",
             []),
        ]
        for raw, expected in entries:
            with self.subTest(raw=raw), patch.dict(os.environ, {ablesci.ENV_ACCOUNTS: raw}):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(ablesci.get_accounts(), expected)
                self.assertNotIn("invalid-private-password", output.getvalue())
                for _, password in expected:
                    self.assertNotIn(password, output.getvalue())

    def test_csrf_meta_and_legacy_input(self):
        bot = ablesci.AbleSciAuto("a@example.com", "fake", notifier=Mock())
        for html, expected in [
            ('<meta name="csrf-token" content="new"><input name="_csrf" value="old">', "new"),
            ('<input name="_csrf" value="old">', "old"),
            ('<meta name="csrf-token" content=" "><input name="_csrf" value="old">', "old"),
            ('<html>no token</html>', ""),
        ]:
            with self.subTest(html=html):
                bot.session = Mock()
                bot.session.get.return_value = Mock(status_code=200, text=html)
                self.assertEqual(bot.get_csrf_token(), expected)
        bot.session.get.side_effect = ablesci.requests.Timeout("offline timeout")
        self.assertEqual(bot.get_csrf_token(), "")

    def test_failures_propagate_to_workflow(self):
        for login_ok, sign_ok, expected in [(False, True, False), (True, False, False), (True, True, True)]:
            bot = ablesci.AbleSciAuto("a@example.com", "fake", notifier=Mock())
            bot.login = Mock(return_value=login_ok)
            bot.sign_in = Mock(return_value=sign_ok)
            bot.get_user_info = Mock()
            bot.display_summary = Mock()
            with patch.object(ablesci.time, "sleep"):
                self.assertIs(bot.run(), expected)
            if not login_ok:
                bot.sign_in.assert_not_called()

        notifier = Mock(notify_enabled=False)
        with patch.object(ablesci, "Notifier", return_value=notifier), patch.object(ablesci, "get_accounts", return_value=[]):
            self.assertEqual(ablesci.main(), 1)
        for results, code in [([True, False], 1), ([True, True], 0)]:
            with patch.object(ablesci, "Notifier", return_value=notifier), patch.object(
                ablesci, "get_accounts", return_value=[("a@example.com", "fake"), ("b@example.com", "fake")]
            ), patch.object(ablesci.AbleSciAuto, "run", side_effect=results):
                self.assertEqual(ablesci.main(), code)

    def test_pushplus_uses_https_and_timeout(self):
        with patch.object(sendNotify, "PUSH_PLUS_TOKEN", "fake"), patch.object(
            sendNotify.requests, "post"
        ) as post, contextlib.redirect_stdout(io.StringIO()):
            post.return_value.json.return_value = {"code": 200}
            sendNotify.pushplus_bot("test", "test")
            self.assertEqual(post.call_args.args[0], "https://www.pushplus.plus/send")
            self.assertEqual(post.call_args.kwargs["timeout"], 30)


if __name__ == "__main__":
    unittest.main()
