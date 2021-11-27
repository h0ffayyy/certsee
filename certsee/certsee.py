#!/usr/bin/env python3

from crtsh import crtshAPI
import os
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

def output_to_file(shodan_results, args):
    """ writes results to a file """
    output_file = args.out

    print("[+] Writing results to file...")

    # check if file already exists
    if os.path.isfile(output_file):
        print(f'[!] File "{output_file}" already exists! Overwrite?')
        
        val = ""
        
        while val != "Y" or val != "y" or val != "N" or val != "n":
            val = input("Y/N: ")

            if val == "N" or val == "n":
                print('[!] Cancelling file write.')
                return
            elif val == "Y" or val == "y":
                break
            else:
                print("[!] Please enter Y or N")

    f = open(output_file, "w")
    for result in shodan_results:
        f.write(json.dumps(result))
        f.write("\n")
    f.close()

    return


def query_shodan(crtsh_results, args):
    """ check shodan for infra using certificate serial number 
    
    Params:
        crtsh_results - list of ssl cert serials to query shodan
        shodan_key - a string representing a Shodan API token
    """
    # for each certifcate returned from crt.sh, query Shodan using the serial 
    # number and return IP addresses for hosts that match
    shodan_key = args.token
    api = Shodan(shodan_key)
    shodan_results = []
    
    print("[+] Querying Shodan for certificate serial numbers")
    
    for cert in crtsh_results:
        shodan_result = {}
        serial_num = cert['serial_number']
        common_name = cert['common_name']
        query = f'ssl.cert.serial:{serial_num}'

        shodan_result['cert_serial'] = serial_num
        shodan_result['cert_common_name'] = common_name
        shodan_result['ips'] = []
        shodan_result['hostnames'] = []

        print(f'[+] Checking serial {serial_num}')
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
                    shodan_result['ips'].append(service['ip_str'])
                    for hostname in service['hostnames']:
                        print(hostname)
                        shodan_result['hostnames'].append(hostname)

            else:
                if global_verbose == True:
                    print(f'[+] No results found for serial: {serial_num}')
                continue

        shodan_results.append(shodan_result)
    return shodan_results


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

    for item in result:
        result_timestamp = parse(item["entry_timestamp"])

        if now-timedelta(days=args.timeframe) <= result_timestamp <= now:
            #print(f'[+] Found one! {result[item]["entry_timestamp"]}')
            # check for any duplicate serial numbers
            if not any(s["serial_number"] == item["serial_number"] for s in recent_certs):
                if len(item["serial_number"]) >= 32:
                    recent_certs.append(item)

    print(f'[+] Found {len(recent_certs)} certificates in last {args.timeframe} days for query: {domain}')

    return recent_certs


def parse_arguments():
    """ parse cli options 
    
    Returns:
        args - the arguments selected by the user
    """
    global global_verbose
    
    # display options
    parser = argparse.ArgumentParser(prog='certsee.py', description='Query crt.sh and find associated infrastructure in Shodan')
    #TODO parser.add_argument('-c', '--csv', help='output to csv', action='store_true')
    parser.add_argument('-d', '--domain', type=str, help='crt.sh domain query string, example: example.com')
    #TODO parser.add_argument('-j', '--json', help='output to json', action='store_true')
    #TODO parser.add_argument('-l', '--limit', type=int, help='limit number of results from crt.sh')
    parser.add_argument('-o', '--out', type=str, help='output to file, specify filename')
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
        shodan_results = query_shodan(crtsh_results, args)

        if args.out:
            output_to_file(shodan_results, args)
    
    print("[+] Done!")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print('Execution interrupted!')
