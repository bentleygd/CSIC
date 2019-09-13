#!/usr/bin/python
from coreutils import getConfig
from requests import ConnectionError
import osintchck
import argparse


def main():
    # Setting up an argument parser.
    a_parse = argparse.ArgumentParser(description='Open Threat Intel ' +
                                                  'checker.')
    a_parse.add_argument('-I', '--ip', action='store_true',
                         help='Check for IP address')
    a_parse.add_argument('-D', '--dns', action='store_true',
                         help='Check for DNS Name')
    a_parse.add_argument('-U', '--url', action='store_true',
                         help='Check for URL')
    a_parse.add_argument('indicator', type=str, help='Indicator to check ' +
                                                     'for.')
    args = a_parse.parse_args()
    
    # Setting the configuration.
    config = getConfig('config.cnf')
    vt_api_key = config.VTAPI()
    fsb_api_key = config.FSBAPI()

    # Looking for IP info (if applicable).
    if args.ip:
        ip_chck = osintchck.IPOSINT(args.indicator)
        # Attempting to run various checks and making a note if they are
        # not successful.
        try:
            vt = ip_chck.VTChck(vt_api_key)
            if vt == 200:
                print ip_chck.vt_results
        except ConnectionError:
            print('Unable to connect to VirusTotal due to network ' +
                  'problems.')

        try:
            tc = ip_chck.TCChck()
            if tc == 200:
                print ip_chck.tc_mw
        except ConnectionError:
            print('Unable to connect to ThreatCrowd due to network ' +
                  'problems.')
        
        try:
            tm = ip_chck.TMChck()
            if tm == 200:
                print ip_chck.tm_mw
        except ConnectionError:
            print('Unable to connect to ThreatMiner due to network ' +
                  'problems.')

        try:
            fsb = ip_chck.FSBChck(fsb_api_key)
            if fsb == 200:
                print ip_chck.fsb_mw
        except ConnectionError:
            print('Unable to connect to Hybrid Analysis due to network ' +
                  'problems.')

        try:
            tbl = ip_chck.TBLChck()
            print ip_chck.tbl_status
        except ConnectionError:
            print('Unable to retrieve the Talos IP blacklist due to ' +
                  'network problems.')

        try:
            uh = ip_chck.UHChck()
            if uh == 'ok':
                print ip_chck.uh_results
            else:
                print uh
        except ConnectionError:
            print('Unable to connect to URLHaus due to network ' +
                  'problems.')


if __name__ == '__main__':
    main()
