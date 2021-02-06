#!/usr/bin/env python3

from crtsh.crtsh import crtshAPI
import sys
import time
import json
import requests
from shodan import Shodan
import argparse
from datetime import datetime, timedelta
from dateutil.parser import parse


global_verbose = False

CRTSH_TIMEFRAME = 2

def query_shodan(crtsh_results, shodan_key):
    """ check shodan for infra using certificate serial number 
    
    Params:
        crtsh_results - list of ssl cert serials to query shodan
        shodan_key - a string representing a Shodan API token
    """
    # for each certifcate returned from crt.sh, query Shodan using the serial 
    # number and return IP addresses for hosts that match
    api = Shodan(shodan_key)
    
    print("[+] Querying Shodan for Certificate Serials...")
    
    for cert in crtsh_results:
        serial_num = cert['serial_number']
        common_name = cert['common_name']
        query = f'ssl.cert.serial:{serial_num}'

        try:
            result = api.search(query)
        except Exception as e:
            print(f'Error: {e}')
            sys.exit(1)
        else:
            time.sleep(1)
            if result['total'] != 0:
                print(f'[!] Found infrastructure for serial: {serial_num} and common name: {common_name}')
                for service in result['matches']:
                    print(service['ip_str'])
            else:
                if global_verbose == True:
                    print(f'[+] No results found for serial: {serial_num}')
                continue


def query_crtsh(args):
    """ query crt.sh for the given domain 
    
    Params:
        args - arguments provided at runtime

    Returns:
        certs - a list of certificates returned from the crt.sh query
    """
    domain = args.domain
    result = crtshAPI().search(domain)
    #print(result[0])

    now = datetime.now()
    recent_certs = []

    print(f'[+] Querying crt.sh for: {domain}')
    
    for item in range(len(result)):
        result_timestamp = parse(result[item]["entry_timestamp"])

        if now-timedelta(days=args.timeframe) <= result_timestamp <= now:
            #print(f'[+] Found one! {result[item]["entry_timestamp"]}')
            # check for any duplicate serial numbers
            if not any(s["serial_number"] == result[item]["serial_number"] for s in recent_certs):
                recent_certs.append(result[item])

    print(f'[+] Found {len(recent_certs)} certificates in last {args.timeframe} days for query: {domain}')

    return recent_certs


def parse_arguments():
    """ parse cli options 
    
    Returns:
        args - the arguments selected by the user
    """
    global global_verbose
    
    # display options
    parser = argparse.ArgumentParser(prog='crtshmon.py', description='Query crt.sh and find associated IPs in Shodan')
    #TODO parser.add_argument('-c', '--csv', help='output to csv', action='store_true')
    parser.add_argument('-d', '--domain', type=str, help='crt.sh domain query string, example: example.com')
    #TODO parser.add_argument('-j', '--json', help='output to json', action='store_true')
    #TODO parser.add_argument('-l', '--limit', type=int, help='limit number of results from crt.sh')
    parser.add_argument('-o', '--out', type=str, help='output to file')
    #TODO parser.add_argument('-r', '--reverse', help='get oldest results from crt.sh first', action='store_true')
    parser.add_argument('-t', '--token', type=str, help='your Shodan API Token')
    parser.add_argument('-T', '--timeframe', type=int, default=CRTSH_TIMEFRAME, help='how far back to search crt.sh certificates in days, defaults to 2')
    parser.add_argument('-v', '--verbose', help='verbose output', action='store_true')
    args = parser.parse_args()

    global_verbose = args.verbose

    # set hardcoded domain query if not specified when calling the script
    if args.domain is None:
        print('[!] Please provide a domain!')
        sys.exit(1)

    # set hardcoded Shodan API token if not specified when calling the script
    if args.token is None:
        print('[!] Please provide your Shodan API token!')
        sys.exit(1)

    return args


def main():
    """ main! """

    args = parse_arguments()
    crtsh_results = query_crtsh(args)

    if len(crtsh_results) == 0:
        sys.exit(0)
    else:
        query_shodan(crtsh_results, args.token)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print('Execution interruped!')
