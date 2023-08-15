#!/usr/bin/env python3
from tabulate import tabulate
import argparse
import pandas as pd
import os
import re
import time
import sys
sys.stdout.reconfigure(encoding='utf-8')

from my_utils.cons import *
from my_utils.helper import *
from alive_progress import alive_it
from alive_progress import alive_bar
from alive_progress.styles import showtime
from alive_progress import config_handler
from alive_progress.styles import showtime, Show

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

parser = argparse.ArgumentParser(description="RiskLogix- Intelligent Risk scoring tool",
                                 usage='main.py -c CVE-2XXX-XXXX', epilog='CSOC@informatica.com')
group = parser.add_mutually_exclusive_group(required=True)
#group.add_argument('--foo',action=.....)
#group.add_argument('--bar',action=.....)
group.add_argument('-c', '--cve', type=str, help='Unique CVE-ID', required=False, metavar='')
group.add_argument('-f', '--file', type=argparse.FileType('r'), help='TXT file with CVEs (One per Line)',
                    required=False, metavar='')
group.add_argument('-l', '--list', help='Space separated list of CVEs', nargs='+', required=False, metavar='')
parser.add_argument('-e', '--epss', type=float, help='EPSS threshold (Default 0.2)', default=0.2, metavar='')
parser.add_argument('-n', '--cvss', type=float, help='CVSS threshold (Default 6.0)', default=6.0, metavar='')
parser.add_argument('-o', '--output', type=str, help='Output filename', required=False, metavar='')
parser.add_argument('-v', '--verbose', help='Verbose mode', action='store_true')

args = parser.parse_args()
warning_m = ""
verbos=False
if __name__ == '__main__':
    # standard args
    #print(os.name)
    #showtime(Show.BARS)
    if os.name=='nt':
        config_handler.set_global(length=20, spinner='stars',theme="classic")
    else:
        config_handler.set_global(length=20, spinner='stars',theme="smooth")
    epss_threshold = args.epss
    cvss_threshold = args.cvss
    outputhead = HEADER
    cve_list = []
    threads = []

    if args.verbose:
        outputhead = V_HEADER
        #pd.DataFrame()
        verbos=True
    if args.cve:
        cve_list.append(args.cve)
        if not os.getenv('NIST_API_KEY'):
            print(bcolors.OKGREEN+csocbanner )
            print(bcolors.WARNING+ 'Warning: Not using NIST API key might result in rate limits')
            print(bcolors.ENDC)
            #print(outputhead)


        else:
            print(bcolors.OKBLUE+csocbanner + outputhead)
            print(bcolors.ENDC)
    elif args.list:
        cve_list = args.list
        if not os.getenv('NIST_API_KEY'):
            if len(cve_list) > 75:
                warning_m = "Large number of CVEs detected, requests will be throttled to avoid API issues"
            print(bcolors.OKBLUE+csocbanner)
            print(bcolors.WARNING+warning_m + '\n'
                  + 'Warning: Using this tool without specifying a NIST API may result in errors' )
            print(bcolors.ENDC)
            #print(outputhead)
        else:
            print(bcolors.OKBLUE+csocbanner)
            #print(outputhead)
    elif args.file:
        cve_list = [line.rstrip() for line in args.file]
        if not os.getenv('NIST_API_KEY'):
            if len(cve_list) > 75:
                warning_m = "Large number of CVEs detected"
            print(csocbanner)
            print(bcolors.WARNING+warning_m + '\n'
                  + 'Warning: Using this tool without specifying a NIST API may result in errors' )

        else:
            print(bcolors.OKBLUE+csocbanner)
            print(bcolors.ENDC)
            #print(outputhead)

    if args.output:
        with open(args.output, 'w') as output_file:
            output_file.write("cve_id,priority,epss,cvss,cvss_version,cvss_severity,cisa_kev" + "\n")

    # Check if any arguments are provided
    if not any(vars(args).values()):
        parser.error("No arguments provided. Please supply at least one argument.")

    print(bcolors.ENDC)
    #print(outputhead)
    output=[]
    with alive_bar(len(cve_list)) as bar:
        for cve in cve_list:
        #with alive_bar(len(cve_list)) as ba

            if os.getenv('NIST_API_KEY'):
                API=os.getenv('NIST_API_KEY')
            else:
                API=''
            if len(cve_list) > 75 and not os.getenv('NIST_API_KEY'):
            # @aabansal please check if we need to handle this
                print()

            if not re.match(r"((CVE|cve)-\d{4}-\d+$)", cve):
                print(bcolors.FAIL + f"Oops!!! {cve} - CVEs should be provided in the standard format CVE-YYYY-NNNN")
                if verbos:
                    df = pd.DataFrame([[cve,'Invalid CVE','Invalid CVE','Invalid CVE','Invalid CVE']], columns = ['CVE', 'CVSS','EPSS','CISA','INFA Severity'])
                else:

                    df = pd.DataFrame([[cve,'Invalid CVE']], columns = ['CVE', 'INFA Severity'])
                pass
            else:
                if re.match(r"cve-\d{4}-\d+$",cve):
                    cve=cve.upper()


                #output+="\n "+cve
                #bar.text('processing CVE '+ cve)
                output=process(cve,bar,output,verbos,API)
                if verbos:
                    df = pd.DataFrame(output, columns = ['CVE', 'CVSS','EPSS','CISA','INFA Severity'])
                else:

                    df = pd.DataFrame(output, columns = ['CVE', 'INFA Severity'])
                #print(df)
            bar()

    print(tabulate(df, headers='keys', tablefmt='psql'))
    print("Report generated ./Risk_output.html")
    df.to_html('Risk_output.html')


