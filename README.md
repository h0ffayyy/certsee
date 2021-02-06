# certsee

Simple utility to query crt.sh and find associated infrastructure using Shodan.

## Requirements

Uses the following:

* [PaulSec's Unofficial crt.sh Python API](https://github.com/PaulSec/crt.sh)
* shodan

See `requirements.txt`

## Usage

```
usage: crtshmon.py [-h] [-d DOMAIN] [-o OUT] [-t TOKEN] [-T TIMEFRAME] [-v]

Query crt.sh and find associated IPs in Shodan

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