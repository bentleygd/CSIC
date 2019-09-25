#!/usr/bin/python
from coreutils import getConfig, hashFile
from requests import ConnectionError
from argparse import ArgumentParser
import validate
import osintchck


def main():
    # Setting up an argument parser.
    a_parse = ArgumentParser(description='Open Threat Intel checker.')
    a_parse.add_argument('-I', '--ip', action='store_true',
                         help='Check for IP address info.')
    a_parse.add_argument('-D', '--dns', action='store_true',
                         help='Check for DNS info.')
    a_parse.add_argument('-U', '--url', action='store_true',
                         help='Check for URL info.')
    a_parse.add_argument('-F', '--file', action='store_true',
                         help='Check for File info.')
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
        if not validate.validateIP(args.indicator):
            print 'Invalid IP address provided as input.'
            exit(1)
        ip_chck = osintchck.IPOSINT(args.indicator)

        try:
            vt = ip_chck.VTChck(vt_api_key)
            if vt == 200:
                print '*' * 32
                print 'VT Results:'
                if ip_chck.vt_response == 1:
                    vt_results = ip_chck.vt_results
                    if 'downloads' in vt_results:
                        print 'IP Owner: %s' % vt_results.get('owner')
                        print 'Country: %s' % vt_results.get('country')
                        print 'Malicious URL count: %d' % (
                              vt_results.get('urls')
                              )
                        print 'Malware download count: %d' % (
                              vt_results.get('downloads')
                              )
                        print('Reference URL: ' + 
                              'https://virustotal.com/gui/ip-address/' +
                              args.indicator +
                              '/details')
                    else:
                        print 'IP Owner: %s' % vt_results.get('owner')
                        print 'Country: %s' % vt_results.get('country')
                        print 'Malicious URL count: %d' % (
                              vt_results.get('urls')
                              )
                        print('Reference URL: ' +
                              'https://virustotal.com/gui/ip-address/' +
                              args.indicator +
                              '/details')
                else:
                    print 'Nothing found on VirusTotal.'
            else:
                print('Unable to successfully connnect to VirusTotal. ' +
                      'The HTTP error code is %d\n') % vt
        except ConnectionError:
            print('Unable to connect to VirusTotal due to network ' +
                  'problems.')

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

        try:
            fsb = ip_chck.FSBChck(fsb_api_key)
            if fsb == 200:
                print '*' * 32
                print 'HybridAnalysis Results:'
                print 'Associated malware count: %d' % ip_chck.fsb_mw
            else:
                print('Unable to succesfully connect to Hybrid' +
                      'Analysis.  The HTTP error code is: %d\n') % (fsb)
        except ConnectionError:
            print('Unable to connect to Hybrid Analysis due to network ' +
                  'problems.')

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

        try:
            urlh = ip_chck.UHChck()
            print '*' * 32
            print 'URLHaus Results:'
            if urlh == 'ok':
                u_results = ip_chck.uh_results
                print 'Malicious URL count: %s' % u_results.get('mw_count')
                print 'SURBL status: %s' % u_results.get('surbl')
                print 'Spamhaus DBL status: %s' % u_results.get('shbl')
                print 'Reference URL: %s' % u_results.get('ref_url')
            else:
                print 'URLHaus status: %s' % urlh
        except ConnectionError:
            print('Unable to connect to URLHaus due to network ' +
                  'problems.')

    # Looking for domain info.
    if args.dns:
        if not validate.validateDN(args.indicator):
            print 'Invalid DNS name.  DNS names must be RFC 1035 compliant.'
            exit(1)
        dns_chck = osintchck.DomainOSINT(args.indicator)

        try:
            vt = dns_chck.VTChck(vt_api_key)
            if vt == 200:
                vt_results = dns_chck.vt_results
                print '*' * 32
                print 'VT Results:'
                if dns_chck.vt_response == 1:
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
                        print('Refernce URL: ' +
                              'https://virustotal.com/gui/domain/' +
                              args.indicator +
                              '/details')
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
                        print('Refernce URL: ' +
                              'https://virustotal.com/gui/domain/' +
                              args.indicator +
                              '/details')
                else:
                    print 'No results found on VirsuTotal.'
            else:
                print('Unable to succesfully connect to VirusTotal.  The ' +
                      'HTTP error code is %d\n') % vt
        except ConnectionError:
            print 'Unable to connect to VirusTotal due to network problems.'

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

        try:
            fsb = dns_chck.FSBChck(fsb_api_key)
            if fsb == 200:
                print '*' * 32
                print 'HybridAnalysis Results:'
                print 'Related sample count: %d' % dns_chck.fsb_mw
                if dns_chck.fsb_mw > 0:
                    print('Average sample threat score: %d' %
                          dns_chck.fsb_ts_avg)
            else:
                print('Unable to succesfully connect to HybridAnalysis. ' +
                      'The HTTP error code is %d\n') % fsb
        except ConnectionError:
            print('Unable to connect to HybridAnalyis due to network ' +
                  'problems.')

        try:
            urlh = dns_chck.UHChck()
            print '*' * 32
            print 'URLHaus Results'
            if urlh == 'ok':
                u_results = dns_chck.uh_results
                print 'Associated malware count: %s' % (u_results.get(
                                                        'mw_count'))
                print 'SURBL status: %s' % u_results.get('surbl')
                print 'Spamhaus DBL status: %s' % u_results.get('shbl')
                print 'Reference URL: %s' % u_results.get('ref_url')
            else:
                print 'URLHaus status: %s' % urlh
        except ConnectionError:
            print 'Unable to connect to URLHaus due to network problems.'

    # Looking for URL related info.
    if args.url:
        if not validate.validateURL(args.indicator):
            exit(1)
        domain = args.indicator.split('/')[2]
        if not validate.validateDN(domain):
            print 'Domain name is not compliant with RFC 1035.'
            exit(1)
        u_chck = osintchck.URLOSINT(args.indicator)

        try:
            vt = u_chck.VTChck(vt_api_key)
            if vt == 200:
                print '*' * 32
                print 'VirusTotal Results:'
                if u_chck.vt_response == 1:
                    v_results = u_chck.vc_results
                    print 'Last Scan Date: %s' % v_results.get('scan_date')
                    print('AV Vendor Malicious Detections: %d' %
                          v_results.get('positives'))
                    print 'Reference URL: %s' % v_results.get('ref_url')
                else:
                    print 'Nothing found on VirusTotal for this URL.'
            else:
                print('Unable to succesfully connect to VirusTotal. ' +
                      'HTTP error code is %d\n') % vt
        except ConnectionError:
            print 'Unable to connect to VirusTotal due to network problems.'

        try:
            fsb = u_chck.FSBChck(fsb_api_key)
            if fsb == 200:
                print '*' * 32
                print 'HybridAnalysis Results:'
                print 'Associated Sample Count: %d' % u_chck.fsb_mw
            else:
                print('Unable to successfully connect to HybridAnalysis. ' +
                      'The HTTP error code is: %d\n') % fsb
        except ConnectionError:
            print('Unable to connect to HybridAnalysis due to ' +
                  'network problems.')

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
                print 'Reference URL: %s' % u_results.get('ref_url')
            else:
                print 'URLHaus status: %s' % urlh
        except ConnectionError:
            print 'Unable to connect to URL Haus due to network problems'

    # Looking for file realted info.
    if args.file:
        file_hash = hashFile(args.indicator)
        print 'The hash we are looking for is below.\n%s' % (file_hash)
        f_chck = osintchck.FileOSINT(file_hash)

        try:
            vt = f_chck.VTChck(vt_api_key)
            if vt == 200:
                print '*' * 32
                print 'VirusTotal Results:'
                if f_chck.vt_response == 1:
                    vt_results = f_chck.vt_results
                    print 'AV Vendor Count: %d' % vt_results.get('av_detect')
                    print('Vendor detection percentage: %d' %
                          vt_results.get('av_percentage'))
                    print 'Reference URL: %s' % vt_results.get('ref_url')
                else:
                    print 'Nothing found for the given hash on VirusTotal'
            else:
                print('Unable to succsefully connect to Virus Total. The ' +
                      'HTTP error code is %d\n' % vt)
        except ConnectionError:
            print 'Unable to connect to VirusTotal due to network problems.'

        try:
            fsb = f_chck.FSBChck(fsb_api_key)
            if fsb == 200:
                print '*' * 32
                print 'HybridAnalysis Results:'
                if f_chck.fsb_r_code == 1:
                    f_results = f_chck.fsb_results
                    print 'File verdict: %s' % f_results.get('verdict')
                    print 'Malware family: %s' % f_results.get('m_family')
                else:
                    print 'Nothing found on the given hash on HybridAnalysis.'
            else:
                print('Unable to succesfully connect to HybridAnalysis. ' +
                      'The HTTP error code is: %d\n' % fsb)
        except ConnectionError:
            print('Unable to connect to HybridAnalysis due to network ' +
                  'problems.')


if __name__ == '__main__':
    main()
