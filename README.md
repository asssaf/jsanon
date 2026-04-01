# jsanon
JSON data anonymizer

A CLI tool to anonymize sensitive fields in JSON files while maintaining format and ensuring global consistency.

## Installation

It's recommended to use a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python3 jsanon.py [file] [options]
```

If `file` is not provided, it reads from `stdin`.

### Options

- `-k, --key-pattern`: Regex pattern(s) to match sensitive field names. Can be specified multiple times.
- `-a, --auto`: Automatically infer sensitive fields using common patterns (e.g., ID, Token, Password, Secret, Email, Address, Phone, Name). Also enables partial URL anonymization.
- `-u, --urls`: Anonymize sensitive parts in URLs (long alphanumeric segments) while preserving the URL structure.
- `-s, --seed`: Seed for deterministic anonymization.

### Examples

Anonymize fields matching 'secret' or 'key':
```bash
python3 jsanon.py data.json -k secret -k key
```

Anonymize using auto-inference and a specific seed:
```bash
python3 jsanon.py data.json -a -s 123
```

Anonymize URLs in a file:
```bash
python3 jsanon.py data.json -u
```

Read from stdin:
```bash
cat data.json | python3 jsanon.py -a
```

## Features

- **Format Preservation**: Non-sensitive characters (like dashes, dots, etc.) are preserved. Numbers are replaced by numbers, and letters by letters (maintaining case).
- **Smart Inference**: Uses the `Faker` library to generate realistic replacements for common data types like emails, IP addresses, phone numbers, and coordinates.
- **Partial URL Anonymization**: Instead of replacing full URLs, it identifies and randomizes sensitive parts (subdomains, path segments, query values) that are longer than 5 characters and contain at least one digit, while preserving the domain name and URL structure.
- **Global Consistency**: Any value identified as sensitive is replaced with the same anonymized value everywhere to avoid data leakage. Identical values will get the same replacement across different files if the same seed is used.
- **Determinism**: Providing a seed ensures that the same input always produces the same anonymized output.
