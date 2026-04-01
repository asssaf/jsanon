import json
import subprocess
import unittest
import os
import tempfile
import re

class TestJSAnon(unittest.TestCase):
    def run_jsanon(self, input_data, args=None):
        if args is None:
            args = []
        # Create a temporary file to hold the JSON input
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
            json.dump(input_data, tmp)
            tmp_path = tmp.name

        try:
            # Run the jsanon script as a subprocess
            process = subprocess.Popen(['python3', 'jsanon.py', tmp_path] + args,
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE,
                                       text=True)
            stdout, stderr = process.communicate()
            if process.returncode != 0:
                raise Exception(f"jsanon failed: {stderr}")
            return json.loads(stdout)
        finally:
            # Clean up the temporary file
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_key_pattern_anonymization(self):
        """Test that fields matching the key pattern are anonymized."""
        data = {"sensitive_key": "secret_value", "normal_key": "public_value"}
        result = self.run_jsanon(data, ["-k", "sensitive_key"])

        self.assertNotEqual(result["sensitive_key"], "secret_value")
        self.assertEqual(result["normal_key"], "public_value")
        self.assertEqual(len(result["sensitive_key"]), len("secret_value"))

    def test_auto_inference(self):
        """Test that common sensitive fields are automatically anonymized with --auto."""
        data = {
            "user_id": 12345,
            "user_email": "test@example.com",
            "other_field": "keep_this"
        }
        result = self.run_jsanon(data, ["-a"])

        self.assertNotEqual(result["user_id"], 12345)
        self.assertNotEqual(result["user_email"], "test@example.com")
        self.assertEqual(result["other_field"], "keep_this")
        self.assertIsInstance(result["user_id"], int)

    def test_determinism_with_seed(self):
        """Test that the same seed produces the same anonymized output."""
        data = {"email": "test@example.com"}

        # Run twice with the same seed
        res1 = self.run_jsanon(data, ["-a", "-s", "12345"])
        res2 = self.run_jsanon(data, ["-a", "-s", "12345"])

        # Run once with a different seed
        res3 = self.run_jsanon(data, ["-a", "-s", "67890"])

        self.assertEqual(res1["email"], res2["email"])
        self.assertNotEqual(res1["email"], res3["email"])

    def test_cross_file_consistency(self):
        """Test that the same value in different files gets the same anonymized value with the same seed."""
        data1 = {"user_email": "test@example.com"}
        data2 = {"other_context": "nothing", "contact_email": "test@example.com"}

        res1 = self.run_jsanon(data1, ["-a", "-s", "100"])
        res2 = self.run_jsanon(data2, ["-a", "-s", "100"])

        self.assertEqual(res1["user_email"], res2["contact_email"])

    def test_global_consistency_substring(self):
        """Test that sensitive values are replaced even when they are substrings in non-sensitive fields."""
        data = {
            "email": "john.doe@example.com",
            "message": "Please contact john.doe@example.com for more info."
        }
        result = self.run_jsanon(data, ["-a"])

        anon_email = result["email"]
        self.assertIn(anon_email, result["message"])
        self.assertNotIn("john.doe@example.com", result["message"])

    def test_format_preservation_string(self):
        """Test that string anonymization preserves casing and length."""
        data = {"key": "Abc-123"}
        result = self.run_jsanon(data, ["-k", "key"])
        val = result["key"]

        self.assertEqual(len(val), 7)
        self.assertTrue(val[0].isupper())
        self.assertTrue(val[1:3].islower())
        self.assertEqual(val[3], "-")
        self.assertTrue(val[4:].isdigit())

    def test_nested_structures(self):
        """Test anonymization within nested dictionaries and lists."""
        data = {
            "user": {
                "id": 1,
                "history": [
                    {"action": "login", "ip": "192.168.1.1"},
                    {"action": "logout", "ip": "192.168.1.1"}
                ]
            }
        }
        # Mark "user" as sensitive to anonymize everything inside
        result = self.run_jsanon(data, ["-k", "user"])

        self.assertNotEqual(result["user"]["id"], 1)
        self.assertNotEqual(result["user"]["history"][0]["ip"], "192.168.1.1")
        # Ensure consistency within the same file
        self.assertEqual(result["user"]["history"][0]["ip"], result["user"]["history"][1]["ip"])

    def test_stdin_input(self):
        """Test reading from stdin when no file is provided."""
        data = {"secret": "data"}
        process = subprocess.Popen(['python3', 'jsanon.py', '-k', 'secret'],
                                   stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE,
                                   text=True)
        stdout, stderr = process.communicate(input=json.dumps(data))

        self.assertEqual(process.returncode, 0)
        result = json.loads(stdout)
        self.assertNotEqual(result["secret"], "data")

    def test_url_partial_anonymization(self):
        """Test partial anonymization of URLs."""
        data = {
            "avatar": "https://image.pawsync.com/iot/pet/avatar/image/v1/edcb2a0ffb33c8cefc5c6a07f87f61ab.png",
            "token": "edcb2a0ffb33c8cefc5c6a07f87f61ab"
        }
        result = self.run_jsanon(data, ["-u", "-s", "123"])

        # Check that the hash part is anonymized and consistent
        anon_token = result["token"]
        self.assertNotEqual(anon_token, "edcb2a0ffb33c8cefc5c6a07f87f61ab")
        self.assertIn(anon_token, result["avatar"])
        self.assertTrue(result["avatar"].startswith("https://image.pawsync.com/iot/pet/avatar/image/v1/"))
        self.assertTrue(result["avatar"].endswith(".png"))

    def test_url_subdomain_anonymization(self):
        """Test anonymization of subdomains in URLs."""
        data = {"url": "https://sensitive123.pawsync.com/path"}
        result = self.run_jsanon(data, ["-u"])

        self.assertNotIn("sensitive123", result["url"])
        self.assertIn(".pawsync.com/path", result["url"])

    def test_url_query_anonymization(self):
        """Test anonymization of query parameters in URLs."""
        data = {"url": "https://example.com/api?token=SECRET999&v=1"}
        result = self.run_jsanon(data, ["-u"])

        self.assertNotIn("SECRET999", result["url"])
        self.assertIn("token=", result["url"])
        self.assertIn("&v=1", result["url"])

    def test_url_in_random_field(self):
        """Test that URLs are anonymized even when the field name is not sensitive."""
        data = {"unrelated_field": "https://image.pawsync.com/path/SECRET123"}
        result = self.run_jsanon(data, ["-u"])

        self.assertNotIn("SECRET123", result["unrelated_field"])
        self.assertIn("https://image.pawsync.com/path/", result["unrelated_field"])

    def test_url_no_digit_segment(self):
        """Test that segments without digits are not anonymized."""
        data = {"url": "https://example.com/deviceImage/v1/SECRET123"}
        result = self.run_jsanon(data, ["-u"])

        self.assertIn("/deviceImage/v1/", result["url"])
        self.assertNotIn("SECRET123", result["url"])

if __name__ == '__main__':
    unittest.main()
