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
                print '*' * 32
                print 'VT Results'
                vt_results = ip_chck.vt_results
                if 'downloads' in vt_results:
                    print 'IP Owner: %s' % vt_results.get('owner')
                    print 'Country: %s' % vt_results.get('country')
                    print 'Malicious URL count: %d' % vt_results.get('urls')
                    print 'Malware download count: %d' % (
                          vt_results.get('downloads')
                          )
                else:
                    print 'IP Owner: %s' % vt_results.get('owner')
                    print 'Country: %s' % vt_results.get('country')
                    print 'Malicious URL count: %d' % vt_results.get('urls')

        except ConnectionError:
            print('Unable to connect to VirusTotal due to network ' +
                  'problems.')

        try:
            tc = ip_chck.TCChck()
            if tc == 200:
                print '*' * 32
                print 'ThreatCrowd Results'
                print 'Associated malware count: %d' % ip_chck.tc_mw
        except ConnectionError:
            print('Unable to connect to ThreatCrowd due to network ' +
                  'problems.')

        try:
            tm = ip_chck.TMChck()
            if tm == 200:
                print '*' * 32
                print 'ThreatMiner Results'
                print 'Associated malware count: %d' % ip_chck.tm_mw
        except ConnectionError:
            print('Unable to connect to ThreatMiner due to network ' +
                  'problems.')

        try:
            fsb = ip_chck.FSBChck(fsb_api_key)
            if fsb == 200:
                print '*' * 32
                print 'Hybrid Analysis Results'
                print 'Associated malware count: %d' % ip_chck.fsb_mw
        except ConnectionError:
            print('Unable to connect to Hybrid Analysis due to network ' +
                  'problems.')

        try:
            ip_chck.TBLChck()
            print '*' * 32
            print 'Talos Blacklist Check'
            print 'Blacklist status: %s' % ip_chck.tbl_status
        except ConnectionError:
            print('Unable to retrieve the Talos IP blacklist due to ' +
                  'network problems.')

        try:
            urlh = ip_chck.UHChck()
            if urlh == 'ok':
                u_results = ip_chck.uh_results
                print '*' * 32
                print 'URLHaus Results'
                print 'Malicious URL count: %s' % u_results.get('mw_count')
                print 'SURBL status: %s' % u_results.get('surbl')
                print 'Spamhaus DBL Status: %s' % u_results.get('shbl')
            else:
                print '*' * 32
                print 'URLHaus Results'
                print 'URLHaus status: %s' % urlh
        except ConnectionError:
            print('Unable to connect to URLHaus due to network ' +
                  'problems.')


if __name__ == '__main__':
    main()
