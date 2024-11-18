from argparse import ArgumentParser
from configparser import ConfigParser
from logging import basicConfig, INFO, getLogger

from libs import validate
from libs import osintchck


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
    # Enabling logging and setting logging configuration.
    log = getLogger('csic')
    basicConfig(
        format='%(asctime)s %(name)s %(levelname)s: %(message)s',
        datefmt='%m/%d/%Y %H:%M:%S',
        level=INFO,
        filename='csic_client.log'
    )
    # Setting the configuration.
    config = ConfigParser()
    config.read('config.cnf')
    # config = get_config('config.cnf')
    # Specifying API keys.
    vt_api_key = config['API']['vt']
    fsb_api_key = config['API']['fsb']
    adb_api_key = config['API']['aipdb']
    otx_api_key = config['API']['otx']

    # Looking for IP info.
    if args.ip:
        if not validate.validateIP(args.indicator):
            print('Invalid IP address provided as input.')
            log.error(
                'IP address %s failed input validation.', args.indicator
            )
            exit(1)
        ip_chck = osintchck.IPOSINT(args.indicator)

        try:
            log.debug('Retrieving CSI for %s', args.indicator)
            vt = ip_chck.VTChck(vt_api_key)
            if vt == 200:
                print('*' * 32)
                print('VT Results:')
                if ip_chck.vt_response == 1:
                    vt_results = ip_chck.vt_results
                    if 'downloads' in vt_results:
                        print('IP Owner: %s' % vt_results.get('owner'))
                        print('Country: %s' % vt_results.get('country'))
                        print('Malicious URL count: %d' % (
                              vt_results.get('urls')
                              ))
                        print('Malware download count: %d' % (
                              vt_results.get('downloads')
                              ))
                        print('Reference URL: ' +
                              'https://virustotal.com/gui/ip-address/' +
                              args.indicator +
                              '/details')
                    else:
                        print('IP Owner: %s' % vt_results.get('owner'))
                        print('Country: %s' % vt_results.get('country'))
                        print('Malicious URL count: %d' % (
                              vt_results.get('urls')
                              ))
                        print('Reference URL: ' +
                              'https://virustotal.com/gui/ip-address/' +
                              args.indicator +
                              '/details')
                else:
                    print('Nothing found on VirusTotal.')
            else:
                print('Unable to successfully connnect to VirusTotal. ' +
                      'The HTTP error code is %d\n') % vt
        except ConnectionError:
            print('Unable to connect to VirusTotal due to network ' +
                  'problems.')

        try:
            fsb = ip_chck.FSBChck(fsb_api_key)
            if fsb == 200:
                print('*' * 32)
                print('HybridAnalysis Results:')
                print('Associated malware count: %d' % ip_chck.fsb_mw)
            else:
                print('Unable to succesfully connect to Hybrid' +
                      'Analysis.  The HTTP error code is: %d\n' % fsb)
        except ConnectionError:
            print('Unable to connect to Hybrid Analysis due to network ' +
                  'problems.')

        try:
            tbl = ip_chck.TBLChck()
            print('*' * 32)
            print('Talos Blacklist Check:')
            if tbl == 200:
                print('Blacklist status: %s' % ip_chck.tbl_status)
            else:
                print('Talos Return Code: %d' % tbl)
        except ConnectionError:
            print('Unable to retrieve the Talos IP blacklist due to ' +
                  'network problems.')

        try:
            urlh = ip_chck.UHChck()
            print('*' * 32)
            print('URLHaus Results:')
            if urlh == 'ok':
                u_results = ip_chck.uh_results
                print('Malicious URL count: %s' % u_results.get('mw_count'))
                print('SURBL status: %s' % u_results.get('surbl'))
                print('Spamhaus DBL status: %s' % u_results.get('shbl'))
                print('Reference URL: %s' % u_results.get('ref_url'))
            else:
                print('URLHaus status: %s' % urlh)
        except ConnectionError:
            print('Unable to connect to URLHaus due to network ' +
                  'problems.')
        log.debug('Finished retrieving CSI for %s', args.indicator)

        adb = ip_chck.AIDBCheck(adb_api_key)
        print('*' * 32)
        print('Abuse IP DB Results:')
        if adb == 200:
            a_results = ip_chck.adb_results
            print('IP Report Count: %s' % a_results['report_count'])
            print('Abuse Confidence Score: %s' % a_results['confidence_score'])
        else:
            print('%d response code from Abuse IP DB API' % adb)

        try:
            otx = ip_chck.OTXCheck(otx_api_key)
            print('*' * 32)
            print('AlienVault OTX:')
            if otx == 200:
                otx_data = ip_chck.otx_results
                if 'country' in otx_data:
                    print(
                        'AlienVault IP Reputation: %d'
                        % otx_data['reputation']
                    )
                    print(
                        'AlienVault Pulse Count: %d'
                        % otx_data['pulse_count']
                    )
                    print('Country: %s' % otx_data['country'])
                else:
                    print(
                        'AlienVault IP Reputation: %d'
                        % otx_data['reputation']
                    )
                    print(
                        'AlienVault Pulse Count: %d'
                        % otx_data['pulse_count']
                    )
            else:
                print('%d response code from OTX.' % otx)
        except ConnectionError:
            print('Unable to connect to OTX due to network problems.')

    # Looking for domain info.
    if args.dns:
        if not validate.validateDN(args.indicator):
            print('Invalid DNS name.  DNS names must be RFC 1035 compliant.')
            log.error('%s failed DNS name input validation', args.indicator)
            exit(1)
        dns_chck = osintchck.DomainOSINT(args.indicator)

        try:
            vt = dns_chck.VTChck(vt_api_key)
            log.debug(
                'Beginning retrieving domain name CSI for %s', args.indicator
            )
            if vt == 200:
                vt_results = dns_chck.vt_results
                print('*' * 32)
                print('VT Results:')
                if dns_chck.vt_response == 1:
                    if 'downloads' in vt_results:
                        print('Malware downloads: %d' % (
                              vt_results.get('downloads')
                              ))
                        print('URL Categories: %s' % (
                              str(vt_results.get('categories'))
                              ))
                        print('Subdomains: %s' % (
                              str(vt_results.get('subdomains'))
                              ))
                        print('Malicious URL Count: %d' % (
                              vt_results.get('url_count')
                              ))
                        print('Refernce URL: ' +
                              'https://virustotal.com/gui/domain/' +
                              args.indicator +
                              '/details')
                    else:
                        print('URL Categories: %s' % (
                              str(vt_results.get('categories'))
                              ))
                        print('Subdomains: %s' % (
                              str(vt_results.get('subdomains'))
                              ))
                        print('Malicious URL Count: %d' % (
                              vt_results.get('url_count')
                              ))
                        print('Refernce URL: ' +
                              'https://virustotal.com/gui/domain/' +
                              args.indicator +
                              '/details')
                else:
                    print('No results found on VirsuTotal.')
            else:
                print('Unable to succesfully connect to VirusTotal.  The ' +
                      'HTTP error code is %d\n' % vt)
        except ConnectionError:
            print('Unable to connect to VirusTotal due to network problems.')

        try:
            fsb = dns_chck.FSBChck(fsb_api_key)
            if fsb == 200:
                print('*' * 32)
                print('HybridAnalysis Results:')
                print('Related sample count: %d' % dns_chck.fsb_mw)
                if dns_chck.fsb_mw > 0:
                    print('Average sample threat score: %d' %
                          dns_chck.fsb_ts_avg)
            else:
                print('Unable to succesfully connect to HybridAnalysis. ' +
                      'The HTTP error code is %d\n' % fsb)
        except ConnectionError:
            print('Unable to connect to HybridAnalyis due to network ' +
                  'problems.')

        try:
            otx = dns_chck.OTXCheck(otx_api_key)
            if otx == 200:
                print('*' * 32)
                print('AlienVault OTX Results:')
                print('AlienVault pulse count: %d' %
                      dns_chck.otx_results['pulse_count'])
                print('AlienVault OTX Malware Count: %d' %
                      dns_chck.otx_results['malware_count'])
            else:
                print('%d response from AlienVault OTX' % otx)
        except ConnectionError:
            print('Unable to connect to OTX due to network problems.')

        try:
            urlh = dns_chck.UHChck()
            print('*' * 32)
            print('URLHaus Results')
            if urlh == 'ok':
                u_results = dns_chck.uh_results
                print(
                    'Associated malware count: %s' % u_results.get('mw_count')
                )
                print('SURBL status: %s' % u_results.get('surbl'))
                print('Spamhaus DBL status: %s' % u_results.get('shbl'))
                print('Reference URL: %s' % u_results.get('ref_url'))
            else:
                print('URLHaus status: %s' % urlh)
        except ConnectionError:
            print('Unable to connect to URLHaus due to network problems.')
        log.debug(
            'Finished retrieving domain name CSI for %s', args.indicator
        )

    # Looking for URL related info.
    if args.url:
        u_chck = osintchck.URLOSINT(args.indicator)

        try:
            vt = u_chck.VTChck(vt_api_key)
            log.debug('Retrieving URL CSI for %s', args.indicator)
            if vt == 200:
                print('*' * 32)
                print('VirusTotal Results:')
                if u_chck.vt_response == 1:
                    v_results = u_chck.vc_results
                    print('Last Scan Date: %s' % v_results.get('scan_date'))
                    print('AV Vendor Malicious Detections: %d' %
                          v_results.get('positives'))
                    print('Reference URL: %s' % v_results.get('ref_url'))
                else:
                    print('Nothing found on VirusTotal for this URL.')
            else:
                print('Unable to succesfully connect to VirusTotal. ' +
                      'HTTP error code is %d\n' % vt)
        except ConnectionError:
            print('Unable to connect to VirusTotal due to network problems.')

        try:
            fsb = u_chck.FSBChck(fsb_api_key)
            if fsb == 200:
                print('*' * 32)
                print('HybridAnalysis Results:')
                print('Associated Sample Count: %d' % u_chck.fsb_mw)
            else:
                print('Unable to successfully connect to HybridAnalysis. ' +
                      'The HTTP error code is: %d\n' % fsb)
        except ConnectionError:
            print('Unable to connect to HybridAnalysis due to ' +
                  'network problems.')

        try:
            urlh = u_chck.UHChck()
            print('*' * 32)
            print('URLHaus Results:')
            if urlh == 'ok':
                u_results = u_chck.uh_results
                print('Threat Category: %s' % u_results.get('status'))
                print('Google Safe Browsing: %s' % u_results.get('gsb'))
                print('SURBL: %s' % u_results.get('surbl'))
                print('Spamhaus BL: %s' % u_results.get('spamhaus_dbl'))
                print('Reference URL: %s' % u_results.get('ref_url'))
            else:
                print('URLHaus status: %s' % urlh)
        except ConnectionError:
            print('Unable to connect to URL Haus due to network problems')

        try:
            otx = u_chck.OTXCheck(otx_api_key)
            print('*' * 32)
            print('AlienVault OTX Results:')
            if otx == 200:
                print('OTX Pulse Count: %d' % u_chck.otx_results)
            else:
                print('OTX respones code: %s' % otx)
        except ConnectionError:
            print('Unable to connect to OTX due to network problems')
        log.debug('Finished retrieving URL CSI for %s', args.indicator)

    # Looking for file realted info.
    if args.file:
        file_hash = args.indicator
        f_chck = osintchck.FileOSINT(file_hash)

        try:
            vt = f_chck.VTChck(vt_api_key)
            log.debug('Retrieving file related CSI for %s', args.indicator)
            if vt == 200:
                print('*' * 32)
                print('VirusTotal Results:')
                if f_chck.vt_response == 1:
                    vt_results = f_chck.vt_results
                    print('AV Vendor Count: %d' % vt_results.get('av_detect'))
                    print('Vendor detection percentage: %d' %
                          vt_results.get('av_percentage'))
                    print('Reference URL: %s' % vt_results.get('ref_url'))
                else:
                    print('Nothing found for the given hash on VirusTotal')
            else:
                print('Unable to succsefully connect to Virus Total. The ' +
                      'HTTP error code is %d\n' % vt)
        except ConnectionError:
            print('Unable to connect to VirusTotal due to network problems.')

        try:
            fsb = f_chck.FSBChck(fsb_api_key)
            if fsb == 200:
                print('*' * 32)
                print('HybridAnalysis Results:')
                if f_chck.fsb_r_code == 1:
                    f_results = f_chck.fsb_results
                    print('File verdict: %s' % f_results.get('verdict'))
                    print('Malware family: %s' % f_results.get('m_family'))
                else:
                    print('Nothing found on the given hash on ' +
                          'HybridAnalysis.')
            else:
                print('Unable to succesfully connect to HybridAnalysis. ' +
                      'The HTTP error code is: %d\n' % fsb)
        except ConnectionError:
            print('Unable to connect to HybridAnalysis due to network ' +
                  'problems.')

        try:
            otx = f_chck.OTXCheck(otx_api_key)
            print('*' * 32)
            print('AlienVault OTX Results:')
            if otx == 200:
                print('OTX Pulse Count: %d' % f_chck.otx_results['p_count'])
                if f_chck.otx_results['m_families'] is not None:
                    print('OTX Malware Families: %s' %
                          f_chck.otx_results['m_families'])
                else:
                    print('OTX Malware Families: None')
            else:
                print('OTX respones code: %s' % otx)
        except ConnectionError:
            print('Unable to connect to OTX due to network problems')
        log.debug(
            'Finished retrieving file related CSI for %s', args.indicator
        )


if __name__ == '__main__':
    main()
