## Kaspersky Hash Checker (OpenTIP)

A Python CLI tool that reads file hashes from a text file and checks their reputation using the Kaspersky Threat Intelligence Portal (OpenTIP) API.

The tool is designed for SOC analysts, incident responders, malware analysts, and penetration testers who need to enrich large hash datasets safely and reliably.

## Features

- Hash reputation lookup via Kaspersky OpenTIP API

- Supports SHA-256, SHA-1, and MD5

- Automatic rate-limit handling (HTTP 429 backoff)

- Timeout protection (skips slow requests)

- Resume capability using cache

- CSV report generation

- Emoji-based CLI output for quick triage

- Works on Linux, macOS, and Windows

- No external dependencies beyond requests

## Example Output
```
[1/5] e3b0c44298fc1c149afbf4c8996fb924 -> 🟢 SAFE (🟢 Green)
[2/5] 44d88612fea8a8f36de82e1278abb02f -> 🔴 MALICIOUS (🔴 Red)
[3/5] 098f6bcd4621d373cade4e832627b4f6 -> ⚪ UNKNOWN (⚪ Grey)
[4/5] 5d41402abc4b2a76b9719d911017c592 -> 🟡 SUSPICIOUS (🟡 Yellow)
[5/5] d41d8cd98f00b204e9800998ecf8427e -> 🟣 TIMEOUT
```
## Installation

# Clone the repository:
```
git clone https://github.com/0x9Fahad/KChecker
cd KChecker
```

# Install dependency:
```
pip install requests
```
# API Key Setup

You need a Kaspersky OpenTIP API key.

# Set it as an environment variable:

# Linux / macOS
```
export KASPERSKY_API_KEY="YOUR_API_KEY"
```
# Windows PowerShell
```
setx KASPERSKY_API_KEY "YOUR_API_KEY"
```
## Usage

Basic run:
```
python3 KChecker.py -i hashes.txt
```
## Options
Specify output file
```
python3 KChecker.py -i hashes.txt -o results.csv
```
Limit number of hashes (testing)
```
python3 KChecker.py -i hashes.txt --max 10
```

Adjust timeout
```
python3 KChecker.py -i hashes.txt --read-timeout 120
```

Adjust rate-limit pacing
```
python3 KChecker.py -i hashes.txt --sleep 1
```

Disable emojis
```
python3 KChecker.py -i hashes.txt --no-emoji
```

## Input Format

hashes.txt should contain one hash per line:
```
e3b0c44298fc1c149afbf4c8996fb924
44d88612fea8a8f36de82e1278abb02f
098f6bcd4621d373cade4e832627b4f6
```

Empty lines and comments (#) are ignored.

## Output Files

After execution, the tool creates:
~~~
kaspersky_results.csv
kaspersky_cache.json
~~~

- CSV columns

- hash

- verdict

- zone

- http_status

- parse_note

- error

- kaspersky_portal

## Verdict Mapping

The tool uses the OpenTIP Zone field:
```
Zone	Verdict
Green	SAFE
Yellow	SUSPICIOUS
Red	MALICIOUS
Grey	UNKNOWN
Cache Behavior
```
# The tool automatically caches results to:
```
kaspersky_cache.json
```

# This allows:

- Safe interruption

- Resume without re-querying

- Reduced API usage

- To start fresh:

- rm kaspersky_cache.json

- Rate Limiting

- The script automatically:

- Retries HTTP 429 responses

- Uses exponential backoff

- Skips hashes that exceed timeout

## Recommended settings:
```
--sleep 1 --read-timeout 120
```
# Best Practices

- Prefer SHA-256 hashes

- Use --max for testing

- Keep cache enabled for large datasets

- Stop the run if you see repeated rate-limit errors
