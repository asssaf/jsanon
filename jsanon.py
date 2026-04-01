import json
import argparse
import sys
import re
import random
import string
import hashlib
from faker import Faker

class JSONAnonymizer:
    def __init__(self, key_patterns, auto=False, seed=None):
        self.faker = Faker()
        self.seed = seed
        # We still set a global seed if provided to influence the hashes
        if seed is not None:
            Faker.seed(seed)
            random.seed(seed)
            self.faker.seed_instance(seed)

        self.key_patterns = [re.compile(p) for p in key_patterns]
        self.auto = auto
        self.auto_field_patterns = [
            re.compile(r'I[Dd]$', re.IGNORECASE),
            re.compile(r'[Tt]oken$', re.IGNORECASE),
            re.compile(r'[Pp]assword', re.IGNORECASE),
            re.compile(r'[Ss]ecret', re.IGNORECASE),
            re.compile(r'[Ee]mail', re.IGNORECASE),
            re.compile(r'[Aa]ddress', re.IGNORECASE),
            re.compile(r'[Pp]hone', re.IGNORECASE),
            re.compile(r'[Nn]ame', re.IGNORECASE)
        ]
        self.value_map = {}
        self.sensitive_values = set()

    def _get_value_seed(self, value):
        """Generate a deterministic seed for a specific value, optionally influenced by a global seed."""
        # Use SHA-256 for a stable hash across different runs and environments
        hasher = hashlib.sha256()
        # Include global seed in the hash if it exists
        if self.seed is not None:
            hasher.update(str(self.seed).encode('utf-8'))
        # Include the value's type and string representation
        hasher.update(type(value).__name__.encode('utf-8'))
        hasher.update(str(value).encode('utf-8'))
        # Return an integer from the hash
        return int(hasher.hexdigest(), 16) % (2**32)

    def is_sensitive_field(self, field_name):
        for pattern in self.key_patterns:
            if pattern.search(field_name):
                return True
        if self.auto:
            for pattern in self.auto_field_patterns:
                if pattern.search(field_name):
                    return True
        return False

    def _preserve_format(self, value):
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            s_val = str(value)
            new_val = ""
            for char in s_val:
                if char.isdigit():
                    new_val += str(random.randint(0, 9))
                else:
                    new_val += char
            try:
                if isinstance(value, int):
                    return int(new_val)
                return float(new_val)
            except ValueError:
                return new_val

        if isinstance(value, str):
            new_val = []
            for char in value:
                if char.isupper():
                    new_val.append(random.choice(string.ascii_uppercase))
                elif char.islower():
                    new_val.append(random.choice(string.ascii_lowercase))
                elif char.isdigit():
                    new_val.append(random.choice(string.digits))
                else:
                    new_val.append(char)
            return "".join(new_val)
        return value

    def _infer_and_generate(self, value):
        if not isinstance(value, str):
            return self._preserve_format(value)

        # Email
        if re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', value):
            return self.faker.email()

        # IP Address (v4 or v6)
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', value):
            return self.faker.ipv4()
        if ":" in value and re.match(r'^[0-9a-fA-F:]+$', value):
            return self.faker.ipv6()

        # Phone Number (simple check)
        if re.match(r'^\+?[\d\s\-\(\)]{7,}$', value):
            return self.faker.phone_number()

        # Coordinates (e.g. "40.7128, -74.0060")
        if re.match(r'^-?\d+(\.\d+)?,\s*-?\d+(\.\d+)?$', value):
            lat, lng = self.faker.latitude(), self.faker.longitude()
            return f"{lat}, {lng}"

        # Names (hard to infer, but let's try if it's 2-3 words capitalized)
        if re.match(r'^[A-Z][a-z]+(\s[A-Z][a-z]+){1,2}$', value):
            return self.faker.name()

        # URLs
        if re.match(r'^https?://', value):
            return self.faker.url()

        return self._preserve_format(value)

    def anonymize_value(self, value):
        if value is None:
            return None

        val_key = (type(value).__name__, value)
        if val_key in self.value_map:
            return self.value_map[val_key]

        # SEEDING: Set seed for this specific value
        val_seed = self._get_value_seed(value)
        random.seed(val_seed)
        self.faker.seed_instance(val_seed)

        anon_val = self._infer_and_generate(value)
        self.value_map[val_key] = anon_val
        return anon_val

    def find_sensitive_values(self, d, sensitive=False):
        if isinstance(d, dict):
            for k, v in d.items():
                self.find_sensitive_values(v, sensitive or self.is_sensitive_field(k))
        elif isinstance(d, list):
            for item in d:
                self.find_sensitive_values(item, sensitive)
        else:
            if sensitive:
                self.sensitive_values.add((type(d).__name__, d))

    def process(self, data, sensitive_context=False):
        if isinstance(data, dict):
            new_dict = {}
            for k, v in data.items():
                is_this_sensitive = sensitive_context or self.is_sensitive_field(k)
                new_dict[k] = self.process(v, is_this_sensitive)
            return new_dict
        elif isinstance(data, list):
            return [self.process(item, sensitive_context) for item in data]
        else:
            val_key = (type(data).__name__, data)
            if sensitive_context or val_key in self.value_map:
                return self.anonymize_value(data)

            if isinstance(data, str):
                new_val = data
                sorted_sensitive = sorted([v[1] for v in self.value_map.keys() if v[0] == 'str'], key=len, reverse=True)
                for s_val in sorted_sensitive:
                    if s_val in new_val:
                        new_val = new_val.replace(s_val, self.value_map[('str', s_val)])
                return new_val

            return data

    def populate_value_map_stably(self):
        def sort_key(x):
            return (x[0], str(x[1]))

        for val_type, val in sorted(list(self.sensitive_values), key=sort_key):
            self.anonymize_value(val)

def main():
    parser = argparse.ArgumentParser(description="Anonymize sensitive fields in JSON data.")
    parser.add_argument("file", nargs="?", default=None,
                        help="JSON file to process (defaults to stdin)")
    parser.add_argument("-k", "--key-pattern", action="append", default=[],
                        help="Regex patterns for sensitive field names")
    parser.add_argument("-a", "--auto", action="store_true",
                        help="Automatically infer sensitive fields using common patterns")
    parser.add_argument("-s", "--seed", type=int, help="Seed for deterministic anonymization")

    args = parser.parse_args()

    if args.file:
        try:
            if args.file == "-":
                data = json.load(sys.stdin)
            else:
                with open(args.file, 'r') as f:
                    data = json.load(f)
        except Exception as e:
            print(f"Error reading file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        try:
            data = json.load(sys.stdin)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON from stdin: {e}", file=sys.stderr)
            sys.exit(1)

    anonymizer = JSONAnonymizer(args.key_pattern, args.auto, args.seed)
    anonymizer.find_sensitive_values(data)
    anonymizer.populate_value_map_stably()
    anonymized_data = anonymizer.process(data)

    print(json.dumps(anonymized_data, indent=2))

if __name__ == "__main__":
    main()
