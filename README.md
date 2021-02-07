# certsee

Simple utility to query crt.sh and find associated infrastructure using Shodan based on certificate serial numbers.

## Requirements

See `requirements.txt`. Uses the following:

* [PaulSec's Unofficial crt.sh Python API](https://github.com/PaulSec/crt.sh)
* shodan

You'll also need a shodan.io API token.

## Installation

First clone the repository: `git clone https://github.com/h0ffayyy/certsee.git`

Install the requirements listed above: `pip3 install -r requirements.txt`

## Usage

```
usage: certsee.py [-h] [-d DOMAIN] [-o OUT] [-t TOKEN] [-T TIMEFRAME] [-v]

Query crt.sh and find associated infrastructure in Shodan

optional arguments:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        crt.sh domain query string, example: example.com
  -o OUT, --out OUT     output to file
  -t TOKEN, --token TOKEN
                        your Shodan API Token
  -T TIMEFRAME, --timeframe TIMEFRAME
                        how far back to search crt.sh certificates in days,
                        defaults to 2
  -v, --verbose         verbose output
```

## Examples

```
python3 certsee.py -d hackerone.com -t XXXXXXXXXXXXXXXXXXXXXXXXX -T 10
[+] Querying crt.sh for: hackerone.com
[+] Found 3 certificates in last 10 days for query: hackerone.com
[+] Querying Shodan for certificate serial numbers
[+] Checking serial 04377e9d1a44dfbe0a7741236218ed3ac3d2
[+] Checking serial 037dca861a6b374c4f99eb64716706c5379e
[+] Checking serial 046e81b1a297ad0d2ae0ff7f1b1c25b167db
[+] Done!
```