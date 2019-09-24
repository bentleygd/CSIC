#!/usr/bin/python
from coreutils import getConfig, hashFile, mailSend
from requests import ConnectionError
from  argparse import ArgumentParser
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
    smtp_server = config.GetSMTPServer()
    rcpts = config.GetReportRcpts()
    sender = config.GetMailSender()

    # Looking for IP info.
    if args.ip:
        if not validate.validateIP(args.indicator):
            exit(1)
        ip_chck = osintchck.IPOSINT(args.indicator)

        try:
            vt = ip_chck.VTChck(vt_api_key)
            if vt == 200:
                if ip_chck.vt_response == 1:
                    vt_results = ip_chck.vt_results
                    if 'downloads' in vt_results:
                        vt_mail = ('IP Owner: %s\n' % (
                                   vt_results.get('owner')) +
                                   'Country: %s\n' % (
                                   vt_results.get('country')) +
                                   'Malicious URL count: %d\n' % (
                                   vt_results.get('urls')) +
                                   'Malware download count: %d\n' % (
                                   vt_results.get('downloads')
                                   ))
                    else:
                        vt_mail = ('IP Owner: %s\n' % (
                                   vt_results.get('owner')) +
                                   'Country: %s\n' % (
                                   vt_results.get('country')) +
                                   'Malicious URL count: %d\n' % (
                                   vt_results.get('urls')
                                   ))
                else:
                    vt_mail = 'Nothing found on VirusTotal.\n'
            else:
                vt_mail = ('Unable to successfully connnect to VirusTotal. ' +
                           'The HTTP error code is %d\n') % vt
        except ConnectionError:
            print('Unable to connect to VirusTotal due to network ' +
                  'problems.')

        try:
            tc = ip_chck.TCChck()
            if tc == 200:
                tc_mail = 'Associated malware count: %d\n' % ip_chck.tc_mw
            else:
                tc_mail = 'No results found on ThreatCrowd\n'
        except ConnectionError:
            print('Unable to connect to ThreatCrowd due to network ' +
                  'problems.')

        try:
            tm = ip_chck.TMChck()
            if tm == 200:
                tm_mail = 'Associated malware count: %d\n' % ip_chck.tm_mw
            else:
                tm_mail = 'No results found on ThreatMiner.\n'
        except ConnectionError:
            print('Unable to connect to ThreatMiner due to network ' +
                  'problems.')

        try:
            fsb = ip_chck.FSBChck(fsb_api_key)
            if fsb == 200:
                fsb_mail = 'Associated malware count: %d\n' % ip_chck.fsb_mw
            else:
                fsb_mail = ('Unable to succesfully connect to Hybrid' +
                            'Analysis.  The HTTP error code is: %d\n') % (fsb)
        except ConnectionError:
            print('Unable to connect to Hybrid Analysis due to network ' +
                  'problems.')

        try:
            tbl = ip_chck.TBLChck()
            if tbl == 200:
                tbl_mail = 'Blacklist status: %s\n' % ip_chck.tbl_status
            else:
                tbl_mail = 'Talos Return Code: %d\n' % tbl
        except ConnectionError:
            print('Unable to retrieve the Talos IP blacklist due to ' +
                  'network problems.')

        try:
            urlh = ip_chck.UHChck()
            if urlh == 'ok':
                u_results = ip_chck.uh_results
                urlh_mail = ('Malicious URL count: %s\n' % (
                             u_results.get('mw_count')) +
                             'SURBL status: %s\n' % u_results.get('surbl') +
                             'Spamhaus DBL status: %s\n' % (
                             u_results.get('shbl')) +
                             'Reference URL: %s\n' % u_results.get('ref_url')
                             )
            else:
                urlh_mail = 'URLHaus status: %s' % urlh
        except ConnectionError:
            print('Unable to connect to URLHaus due to network ' +
                  'problems.')
        # Setting the mail body
        ip_mail_body = ('Indicator: %s\n' % args.indicator +
                        '*' * 32 + '\n' +
                        'VT Results:\n' +
                        vt_mail +
                        '*' * 32 + '\n' +
                        'Threat Crowd Results:\n' +
                        tc_mail +
                        '*' * 32 + '\n' +
                        'ThreatMiner Results:\n' +
                        tm_mail +
                        '*' * 32 + '\n' +
                        'FalconSandBox Results:\n' +
                        fsb_mail +
                        '*' * 32 + '\n' +
                        'Talos Black List Status:\n' +
                        tbl_mail +
                        '*' * 32 + '\n' +
                        'URLHaus Results:\n' +
                        urlh_mail)
        # Sending the mail message
        mailSend(sender, rcpts, 'CSIC IP Info', smtp_server, ip_mail_body)

    # Looking for domain info.
    if args.dns:
        if not validate.validateDN(args.indicator):
            exit(1)
        dns_chck = osintchck.DomainOSINT(args.indicator)

        try:
            vt = dns_chck.VTChck(vt_api_key)
            if vt == 200:
                vt_results = dns_chck.vt_results
                if dns_chck.vt_response == 1:
                    if 'downloads' in vt_results:
                        vt_mail = ('Malware downloads: %d \n' % (
                                   vt_results.get('downloads')) +
                                   'URL Categories: %s \n' % (
                                   str(vt_results.get('categories'))) +
                                   'Subdomains: %s \n' % (
                                   str(vt_results.get('subdomains'))) +
                                   'Malicious URL Count: %d\n' % (
                                   vt_results.get('url_count'))
                                   )
                    else:
                        vt_mail = ('URL Categories: %s \n' % (
                                   str(vt_results.get('categories'))) +
                                   'Subdomains: %s \n' % (
                                   str(vt_results.get('subdomains'))) +
                                   'Malicious URL Count: %d\n' % (
                                   vt_results.get('url_count'))
                                   )
                else:
                    vt_mail = 'No results found on VirsuTotal.\n'
            else:
                vt_mail = ('Unable to succesfully connect to VirusTotal. ' +
                           'The HTTP error code is %d\n') % vt
        except ConnectionError:
            print 'Unable to connect to VirusTotal due to network problems.'

        try:
            tc = dns_chck.TCChck()
            if tc == 200:
                tc_mail = 'Resolve count: %d\n' % (dns_chck.tc_rc)
                for entry in dns_chck.tc_ips:
                    tc_mail = tc_mail + 'IP: %s Resolved Date: %s\n' % (
                              entry.get('ip_address'),
                              entry.get('r_time')
                              )
            else:
                tc_mail = 'No results found on ThreatCrowd\n'
        except ConnectionError:
            print('Unable to connect to ThreatCrowd due to network ' +
                  'problems')

        try:
            tm = dns_chck.TMChck()
            if tm == 200:
                tm_mail = 'Associated malware count: %d\n' % dns_chck.tm_mw
            else:
                tm_mail = 'No results found on ThreatMiner.\n'
        except ConnectionError:
            print 'Unable to connect to ThreatMiner due to network problems.'

        try:
            fsb = dns_chck.FSBChck(fsb_api_key)
            if fsb == 200:
                fsb_mail = 'Related sample count: %d\n' % dns_chck.fsb_mw
                if dns_chck.fsb_mw > 0:
                    fsb_mail = (fsb_mail +
                                ('Average sample threat score: %d\n' %
                                 dns_chck.fsb_ts_avg))
            else:
                fsb_mail = ('Unable to succesfully connect to Hybrid ' +
                            'Analysis. The HTTP error code is %d\n') % fsb
        except ConnectionError:
            print('Unable to connect to HybridAnalyis due to network ' +
                  'problems.')

        try:
            urlh = dns_chck.UHChck()
            if urlh == 'ok':
                u_results = dns_chck.uh_results
                urlh_mail = ('Associated malware count: %s\n' % (
                             u_results.get('mw_count')) +
                             'SURBL status: %s \n' % u_results.get('surbl') +
                             'Spamhaus DBL status: %s \n' % (
                             u_results.get('shbl')) +
                             'Reference URL: %s\n' % u_results.get('ref_url')
                             )
            else:
                urlh_mail = 'URLHaus status: %s' % urlh
        except ConnectionError:
            print 'Unable to connect to URLHaus due to network problems.'
        # Setting the mail message
        dns_mail_body = ('Indicator: %s\n' % args.indicator +
                         '*' * 32 + '\n' +
                         'VT Results:\n' +
                         vt_mail +
                         '*' * 32 + '\n' +
                         'Threat Crowd Results:\n' +
                         tc_mail +
                         '*' * 32 + '\n' +
                         'ThreatMiner Results:\n' +
                         tm_mail +
                         '*' * 32 + '\n' +
                         'FalconSandBox Results:\n' +
                         fsb_mail +
                         '*' * 32 + '\n' +
                         'URLHaus Results:\n' +
                         urlh_mail)
        # Sending the mail message.
        mailSend(sender, rcpts, 'CSIC DNS Info', smtp_server, dns_mail_body)

    # Looking for URL related info.
    if args.url:
        if not validate.validateURL(args.indicator):
            exit(1)
        domain = args.indicator.split('/')[2]
        if not validate.validateDN(domain):
            exit(1)
        u_chck = osintchck.URLOSINT(args.indicator)

        try:
            vt = u_chck.VTChck(vt_api_key)
            if vt == 200:
                if u_chck.vt_response == 1:
                    v_results = u_chck.vc_results
                    vt_mail = ('Last Scan Date: %s\n' % (
                               v_results.get('scan_date')) +
                               'AV Vendor Malicious Detections: %d\n' % (
                               v_results.get('positives')) +
                               'Reference URL: %s\n' % (
                               v_results.get('ref_url'))
                               )
                else:
                    vt_mail = 'Nothing found on VirusTotal for this URL.'
            else:
                vt_mail = ('Unable to succesfully connect to VirusTotal. ' +
                           'HTTP error code is %d\n') % vt
        except ConnectionError:
            print 'Unable to connect to VirusTotal due to network problems.'

        try:
            fsb = u_chck.FSBChck(fsb_api_key)
            if fsb == 200:
                fsb_mail = 'Associated Sample Count: %d\n' % u_chck.fsb_mw
            else:
                fsb_mail = ('Unable to successfully connect to Hybrid ' +
                            ' Analysis.  The HTTP error code is: %d\n') % fsb
        except ConnectionError:
            print('Unable to connect to HybridAnalysis due to ' +
                  'network problems.')

        try:
            urlh = u_chck.UHChck()
            if urlh == 'ok':
                u_results = u_chck.uh_results
                urlh_mail = ('Threat Category: %s\n' % (
                             u_results.get('status')) +
                             'Google Safe Browsing: %s\n' % (
                             u_results.get('gsb')) +
                             'SURBL: %s\n' % u_results.get('surbl') +
                             'Spamhaus BL: %s\n' % (
                             u_results.get('spamhaus_dbl')) +
                             'Reference URL: %s\n' % u_results.get('ref_url')
                             )
            else:
                urlh_mail = 'URLHaus status: %s' % urlh
        except ConnectionError:
            print 'Unable to connect to URL Haus due to network problems'
        # Setting the mail message
        url_mail_body = ('Indicator: %s\n' % args.indicator +
                         '*' * 32 + '\n' +
                         'VT Results:\n' +
                         vt_mail +
                         '*' * 32 + '\n' +
                         'FalconSandBox Results:\n' +
                         fsb_mail +
                         '*' * 32 + '\n' +
                         'URLHaus Results:\n' +
                         urlh_mail)
        # Sending the mail message.
        mailSend(sender, rcpts, 'CSIC URL Info', smtp_server, url_mail_body)

    # Looking for file realted info.
    if args.file:
        file_hash = hashFile(args.indicator)
        f_chck = osintchck.FileOSINT(file_hash)

        try:
            vt = f_chck.VTChck(vt_api_key)
            if vt == 200:
                if f_chck.vt_response == 1:
                    vt_results = f_chck.vt_results
                    vt_mail = ('AV Vendor Count: %d\n' % (
                               vt_results.get('av_detect')) +
                               'Vendor detection percentage: %d\n' % (
                               vt_results.get('av_percentage')) +
                               'Reference URL: %s\n' % (
                               vt_results.get('ref_url'))
                               )
                else:
                    vt_mail = 'Nothing found for the given hash on VirusTotal'
            else:
                vt_mail = ('Unable to succsefully connect to Virus Total. ' +
                           'The HTTP error code is %d\n' % vt)
        except ConnectionError:
            print 'Unable to connect to VirusTotal due to network problems.'

        try:
            fsb = f_chck.FSBChck(fsb_api_key)
            if fsb == 200:
                if f_chck.fsb_r_code == 1:
                    f_results = f_chck.fsb_results
                    fsb_mail = ('File verdict: %s\n' % (
                                f_results.get('verdict')) +
                                'Malware family: %s\n' % (
                                f_results.get('m_family'))
                                )
                else:
                    fsb_mail = ('Nothing found on the given hash on ' +
                                'HybridAnalysis.')
            else:
                fsb_mail = ('Unable to succesfully connect to Hybrid ' +
                            'Analysis.  The HTTP error code is: %d\n' % fsb)
        except ConnectionError:
            print('Unable to connect to HybridAnalysis due to network ' +
                  'problems.')
        # Setting the mail message
        file_mail_body = ('Indicator: %s\n' % args.indicator +
                          'File Hash: %s\n' % file_hash +
                          '*' * 32 + '\n' +
                          'VT Results:\n' +
                          vt_mail +
                          '*' * 32 + '\n' +
                          'FalconSandBox Results:\n' +
                          fsb_mail)
        # Sending the mail message.
        mailSend(sender, rcpts, 'CSIC File Info', smtp_server, file_mail_body)


if __name__ == '__main__':
    main()
