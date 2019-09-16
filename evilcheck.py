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
    # Specifying API keys.
    vt_api_key = config.VTAPI()
    fsb_api_key = config.FSBAPI()

    # Looking for IP info.
    if args.ip:
        ip_chck = osintchck.IPOSINT(args.indicator)

        try:
            vt = ip_chck.VTChck(vt_api_key)
            if vt == 200:
                print '*' * 32
                print 'VT Results:'
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
            else:
                print('Unable to successfully connnect to VirusTotal. ' +
                      'The HTTP error code is %d\n') % vt
        except ConnectionError:
            print('Unable to connect to VirusTotal due to network ' +
                  'problems.')
            pass

        try:
            tc = ip_chck.TCChck()
            print '*' * 32
            print 'ThreatCrowd Results:'
            if tc == 200:
                print 'Associated malware count: %d' % ip_chck.tc_mw
            else:
                print 'No results found on ThreatCrowd'
        except ConnectionError:
            print('Unable to connect to ThreatCrowd due to network ' +
                  'problems.')
            pass

        try:
            tm = ip_chck.TMChck()
            print '*' * 32
            print 'ThreatMiner Results:'
            if tm == 200:
                print 'Associated malware count: %d' % ip_chck.tm_mw
            else:
                print 'No results found on ThreatMiner.'
        except ConnectionError:
            print('Unable to connect to ThreatMiner due to network ' +
                  'problems.')
            pass

        try:
            fsb = ip_chck.FSBChck(fsb_api_key)
            if fsb == 200:
                print '*' * 32
                print 'Hybrid Analysis Results:'
                print 'Associated malware count: %d' % ip_chck.fsb_mw
            else:
                print('Unable to succesfully connect to Hybrid ' +
                      'Analysis.  The HTTP error code is: %d\n') % (fsb)
        except ConnectionError:
            print('Unable to connect to Hybrid Analysis due to network ' +
                  'problems.')
            pass

        try:
            tbl = ip_chck.TBLChck()
            print '*' * 32
            print 'Talos Blacklist Check:'
            if tbl == 200:
                print 'Blacklist status: %s' % ip_chck.tbl_status
            else:
                print 'Talos Return Code: %d' % tbl
        except ConnectionError:
            print('Unable to retrieve the Talos IP blacklist due to ' +
                  'network problems.')
            pass

        try:
            urlh = ip_chck.UHChck()
            print '*' * 32
            print 'URLHaus Results:'
            if urlh == 'ok':
                u_results = ip_chck.uh_results
                print 'Malicious URL count: %s' % u_results.get('mw_count')
                print 'SURBL status: %s' % u_results.get('surbl')
                print 'Spamhaus DBL Status: %s' % u_results.get('shbl')
            else:
                print 'URLHaus status: %s' % urlh
        except ConnectionError:
            print('Unable to connect to URLHaus due to network ' +
                  'problems.')
            pass

    # Looking for domain info.
    if args.dns:
        dns_chck = osintchck.DomainOSINT(args.indicator)
        try:
            vt = dns_chck.VTChck(vt_api_key)
            if vt == 200:
                vt_results = dns_chck.vt_results
                print '*' * 32
                print 'VT Results:'
                if 'downloads' in vt_results:
                    print 'Malware downloads: %d' % (
                          vt_results.get('downloads')
                          )
                    print 'URL Categories: %s' % (
                          str(vt_results.get('categories'))
                          )
                    print 'Subdomains: %s' % (
                           str(vt_results.get('subdomains'))
                          )
                    print 'Malicious URL Count: %d' % (
                          vt_results.get('url_count')
                          )
                else:
                    print 'URL Categories: %s' % (
                          str(vt_results.get('categories'))
                          )
                    print 'Subdomains: %s' % (
                           str(vt_results.get('subdomains'))
                          )
                    print 'Malicious URL Count: %d' % (
                          vt_results.get('url_count')
                          )
            else:
                print('Unable to succesfully connect to VirusTotal.  The ' +
                      'HTTP error code is %d\n') % vt
        except ConnectionError:
            print 'Unable to connect to VirusTotal due to network problems.'
            pass

        try:
            tc = dns_chck.TCChck()
            print '*' * 32
            print 'ThreatCrowd Results'
            if tc == 200:
                print 'Resolve count: %d' % (dns_chck.tc_rc)
                for entry in dns_chck.tc_ips:
                    print 'IP: %s Resolved Date: %s' % (
                          entry.get('ip_address'),
                          entry.get('r_time')
                          )
            else:
                print 'No results found on ThreatCrowd'
        except ConnectionError:
                print('Unable to connect to ThreatCrowd due to network ' +
                      'problems')
                pass

        try:
            tm = dns_chck.TMChck()
            print '*' * 32
            print 'ThreatMiner Results'
            if tm == 200:
                print 'Associated malware count: %d' % dns_chck.tm_mw
            else:
                print 'No results found on ThreatMiner.'
        except ConnectionError:
            print 'Unable to connect to ThreatMiner due to network problems.'
            pass

        try:
            fsb = dns_chck.FSBChck(fsb_api_key)
            if fsb == 200:
                print '*' * 32
                print 'Hybrid Analysis Results:'
                print 'Associated malware count: %d' % dns_chck.fsb_mw
            else:
                print('Unable to succesfully connect to Hybrid Analysis. ' +
                      'The HTTP error code is %d\n') % fsb
        except ConnectionError:
            print('Unable to connect to Hybrid Analyis due to network ' +
                  'problems.')
            pass

        try:
            urlh = dns_chck.UHChck()
            print '*' * 32
            print 'URLHaus Results'
            if urlh == 'ok':
                u_results = dns_chck.uh_results
                print 'Associated malware count: %s' % (u_results.get(
                                                        'mw_count'))
                print 'SURBL status: %s' % u_results.get('surbl')
                print 'Spamhaus DBL Status: %s' % u_results.get('shbl')
            else:
                print 'URLHaus status: %s' % urlh
        except ConnectionError:
            print 'Unable to connect to URLHaus due to network problems.'
            pass

    # Looking for URL related info.
    if args.url:
        u_chck = osintchck.URLOSINT(args.indicator)

        try:
            vt = u_chck.VTChck(vt_api_key)
            if vt == 200:
                v_results = u_chck.vc_results
                print '*' * 32
                print 'VirusTotal Results:'
                print 'Last Scan Date: %s' % v_results.get('scan_date')
                print 'Malicious Detections: %d' % v_results.get('positives')
            else:
                print('Unable to succesfully connect to VirusTotal. ' +
                      'HTTP error code is %d\n') % vt
        except ConnectionError:
            print 'Unable to connect to VirusTotal due to network problems.'
            pass

        try:
            fsb = u_chck.FSBChck(fsb_api_key)
            if fsb == 200:
                print '*' * 32
                print 'Hybrid Analysis Results:'
                print 'Associated Malware Count: %d' % u_chck.fsb_mw
            else:
                print('Unable to successfully connect to Hybrid Analysis. ' +
                      'The HTTP error code is: %d\n') % fsb
        except ConnectionError:
            print('Unable to connect to Hybrid Analysis due to ' +
                  'network problems.')
            pass

        try:
            urlh = u_chck.UHChck()
            print '*' * 32
            print 'URLHaus Results:'
            if urlh == 'ok':
                u_results = u_chck.uh_results
                print 'Threat Category: %s' % u_results.get('status')
                print 'Google Safe Browsing: %s' % u_results.get('gsb')
                print 'SURBL: %s' % u_results.get('surbl')
                print 'Spamhaus BL: %s' % u_results.get('spamhaus_dbl')
            else:
                print 'URLHaus Status: %s' % urlh
        except ConnectionError:
            print 'Unable to connect to URL Haus due to network problems'
            pass


if __name__ == '__main__':
    main()
