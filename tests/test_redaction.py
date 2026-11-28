import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "subscribe"))

from config.models import RenewAccount, StorageConfig, StorageItem
from config.parse import Node
from security.redaction import redact_mapping, redact_url


class RedactionTests(unittest.TestCase):
    def test_redact_mapping_hides_sensitive_values(self):
        source = {
            "username": "demo",
            "password": "secret",
            "headers": {"Authorization": "Bearer token-123", "X-Cookie": "c=abc"},
            "items": [{"token": "t-1"}, {"note": "keep"}],
        }

        result = redact_mapping(source)

        self.assertEqual(result["username"], "demo")
        self.assertEqual(result["password"], "***")
        self.assertEqual(result["headers"]["Authorization"], "***")
        self.assertEqual(result["headers"]["X-Cookie"], "***")
        self.assertEqual(result["items"][0]["token"], "***")
        self.assertEqual(result["items"][1]["note"], "keep")
        self.assertEqual(source["password"], "secret")

    def test_redact_url_strips_credentials_and_sensitive_query(self):
        url = "https://user:secret@example.com/path?token=abc&name=demo"
        self.assertEqual(redact_url(url), "https://example.com/path?token=***&name=demo")

    def test_storage_item_export_hides_sensitive_fields(self):
        item = StorageItem(username="demo", file_id="file-1", password="secret")
        payload = item.to_dict()
        self.assertEqual(payload["username"], "demo")
        self.assertEqual(payload["file_id"], "file-1")
        self.assertEqual(payload["password"], "***")

    def test_renew_account_reads_password_from_environment(self):
        os.environ["TEST_RENEW_PASSWORD"] = "env-secret"
        try:
            node = Node({"email": "demo@example.com", "password_env": "TEST_RENEW_PASSWORD"})
            account = RenewAccount.parse(node)
            self.assertEqual(account.email, "demo@example.com")
            self.assertEqual(account.password, "env-secret")
            self.assertEqual(account.to_dict(), {"email": "demo@example.com", "password_env": "TEST_RENEW_PASSWORD"})
        finally:
            os.environ.pop("TEST_RENEW_PASSWORD", None)

    def test_renew_account_rejects_plaintext_password(self):
        node = Node({"email": "demo@example.com", "password": "plain-secret"})
        with self.assertRaises(Exception):
            RenewAccount.parse(node)

    def test_storage_config_export_hides_token(self):
        node = Node({"engine": "gist", "token": "secret-token", "base": "https://example.com"})
        config = StorageConfig.parse(node)
        payload = config.to_dict()
        self.assertEqual(payload["engine"], "gist")
        self.assertEqual(payload["token"], "***")
        self.assertEqual(payload["base"], "https://example.com")


if __name__ == "__main__":
    unittest.main()
