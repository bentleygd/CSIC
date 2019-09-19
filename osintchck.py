#!/usr/bin/python
from requests import get, post


class IPOSINT:
    def __init__(self, ip):
        self.ip = ip
        self.vt_results = dict()
        self.tc_mw = int()
        self.tm_mw = int()
        self.fsb_mw = int()
        self.tbl_status = str()
        self.uh_results = dict()

    def VTChck(self, vt_api):
        """ Checks VirusTotal for info for a given IP address."""
        url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        params = {'apikey': vt_api, 'ip': self.ip}
        response = get(url, params=params)
        if response.status_code == 200:
            data = response.json()
            if 'detected_downloaded_samples' in data:
                self.vt_results = {
                    'owner': data.get('as_owner'),
                    'country': data.get('country'),
                    'urls': len(data.get('detected_urls')),
                    'downloads': len(data.get('detected_downloaded_samples'))
                }
            else:
                self.vt_results = {
                    'owner': data.get('as_owner'),
                    'country': data.get('country'),
                    'urls': len(data.get('detected_urls'))
                }
        return response.status_code

    def TCChck(self):
        """ Checks ThreatCrowd for info for a given IP."""
        url = 'https://www.threatcrowd.org/searchApi/v2/ip/report/'
        params = {'ip': self.ip}
        data = get(url, params=params).json()
        if data.get('response_code') == '1':
            self.tc_mw = len(data.get('hashes'))
            status_code = 200
        else:
            status_code = 404
        return status_code

    def TMChck(self):
        """Checks ThreatMiner for info for a given IP."""
        url = 'https://api.threatminer.org/v2/host.php'
        params = {'q': self.ip, 'rt': '4'}
        data = get(url, params=params).json()
        if data.get('status_code') == '200':
            self.tm_mw = len(data.get('results'))
        return int(data.get('status_code'))

    def FSBChck(self, fsb_api):
        """Checks hybrid-analysis for info for a given IP."""
        url = 'https://www.hybrid-analysis.com/api/v2/search/terms'
        headers = {'api-key': fsb_api, 'user-agent': 'Falcon'}
        data = {'host': self.ip}
        response = post(url, headers=headers, data=data)
        if response.status_code == 200:
            self.fsb_mw = response.json().get('count')
        return response.status_code

    def TBLChck(self):
        """Checks to see if an IP is on the Talos blacklist."""
        url = 'https://talosintelligence.com/documents/ip-blacklist'
        response = get(url)
        data = response.text.split('\n')
        if self.ip in data:
            self.tbl_status = 'Blacklisted IP'
        else:
            self.tbl_status = 'Non-blacklisted IP'
        return response.status_code

    def UHChck(self):
        """Checks URLHaus for info for a given IP."""
        url = 'https://urlhaus-api.abuse.ch/v1/host/'
        data = {'host': self.ip}
        response = post(url, data=data).json()
        if response.get('query_status') == 'ok':
            uh_bl = response.get('blacklists')
            self.uh_results = {
                'mw_count': response.get('url_count'),
                'surbl': uh_bl.get('surbl'),
                'shbl': uh_bl.get('spamhaus_dbl')
            }
        return response.get('query_status')


class DomainOSINT:
    def __init__(self, domain_name):
        self.domain = domain_name
        self.vt_results = dict()
        self.tc_rc = int()
        self.tc_ips = list()
        self.tm_mw = int()
        self.fsb_mw = int()
        self.fsb_ts = int()
        self.uh_results = dict()

    def VTChck(self, vt_api):
        """Checks VirusTotal for info for a given domain."""
        url = 'https://www.virustotal.com/vtapi/v2/domain/report'
        params = {'apikey': vt_api, 'domain': self.domain}
        response = get(url, params=params)
        if response.status_code == 200:
            data = response.json()
            if data.get('response_code') == 1:
                if 'detected_downloaded_samples' in data:
                    self.vt_results = {
                        'downloads': len(data.get(
                                         'detected_downloaded_samples')),
                        'categories': data.get('categories'),
                        'subdomains': data.get('subdomains'),
                        'url_count': len(data.get('detected_urls'))
                    }
                else:
                    self.vt_results = {
                        'categories': data.get('categories'),
                        'subdomains': data.get('subdomains'),
                        'url_count': len(data.get('detected_urls'))
                    }
        return response.status_code

    def TCChck(self):
        """Checks ThreatCrowd for info for a given domain."""
        url = 'https://www.threatcrowd.org/searchApi/v2/domain/report/'
        params = {'domain': self.domain}
        data = get(url, params=params).json()
        if data.get('response_code') == '1':
            self.tc_rc = len(data.get('resolutions'))
            for entry in data.get('resolutions'):
                self.tc_ips.append({'ip_address': entry.get('ip_address'),
                                   'r_time': entry.get('last_resolved')})
            status_code = 200
        else:
            status_code = 404
        return status_code

    def TMChck(self):
        """Checks ThreatMiner for info for a given domain."""
        url = 'https://api.threatminer.org/v2/domain.php'
        params = {'q': self.domain, 'rt': '4'}
        data = get(url, params=params).json()
        if data.get('status_code') == '200':
            self.tm_mw = len(data.get('results'))
        return int(data.get('status_code'))

    def FSBChck(self, fsb_api):
        """Checks hybrid analysis for info for a given domain."""
        url = 'https://www.hybrid-analysis.com/api/v2/search/terms'
        headers = {'api-key': fsb_api, 'user-agent': 'Falcon'}
        data = {'domain': self.domain}
        response = post(url, headers=headers, data=data)
        if response.status_code == 200:
            self.fsb_mw = response.json().get('count')
            ts = int()
            for result in response.json().get('result'):
                ts = ts + result.get('threat_score')
            self.fsb_ts_avg = ts / len(response.json().get('result'))
        return response.status_code

    def UHChck(self):
        """Checks URLhaus for info for a given domain."""
        url = 'https://urlhaus-api.abuse.ch/v1/host/'
        data = {'host': self.domain}
        response = post(url, data=data).json()
        if response.get('query_status') == 'ok':
            uh_bl = response.get('blacklists')
            self.uh_results = {
                'mw_count': response.get('url_count'),
                'surbl': uh_bl.get('surbl'),
                'shbl': uh_bl.get('spamhaus_dbl')
            }
        return response.get('query_status')


class URLOSINT:
    def __init__(self, b_url):
        self.b_url = b_url
        self.vc_results = dict()
        self.fsb_mw = int()
        self.uh_results = dict()

    def VTChck(self, vt_api):
        """Checks VirusTotal for info for a given URL."""
        url = 'https://www.virustotal.com/vtapi/v2/url/report'
        params = {'apikey': vt_api, 'resource': self.b_url}
        response = get(url, params=params)
        if response.status_code == 200:
            data = response.json()
            if data.get('response_code') == 1:
                self.vc_results = {
                    'scan_date': data.get('scan_date'),
                    'positives': data.get('positives')
                }
        return response.status_code

    def FSBChck(self, fsb_api):
        """Checks hybrid analysis for infor for a given URL."""
        url = 'https://www.hybrid-analysis.com/api/v2/search/terms'
        headers = {'api-key': fsb_api, 'user-agent': 'Falcon'}
        data = {'url': self.b_url}
        response = post(url, headers=headers, data=data)
        if response.status_code == 200:
            self.fsb_mw = response.json().get('count')
        return response.status_code

    def UHChck(self):
        """Checks URLhaus for info for a given URL."""
        url = 'https://urlhaus-api.abuse.ch/v1/url/'
        data = {'url': self.b_url}
        response = post(url, data=data).json()
        if response.get('query_status') == 'ok':
            uh_bl = response.get('blacklists')
            self.uh_results = {
                'status': response.get('threat'),
                'gsb': uh_bl.get('gsb'),
                'surbl': uh_bl.get('surbl'),
                'shbl': uh_bl.get('spamhaus_dbl')
            }
        return response.get('query_status')


class FileOSINT:
    def __init__(self, filehash):
        self.hash = filehash
        self.vt_response = int()
        self.vt_results = dict()
        self.fsb_r_code = int()
        self.fsb_results = dict()

    def VTChck(self, vt_api):
        """Checks VirusTotal for info for a given file hash."""
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': vt_api, 'resource': self.hash}
        response = get(url, params=params)
        if response.status_code == 200:
            data = response.json()
            self.vt_response = data.get('response_code')
            if data.get('response_code') == 1:
                vt_percent = int(round(
                             float(data.get('positives'))
                             / float(data.get('total'))
                             , 2) * 100)
                self.vt_results = {
                    'av_detect': data.get('positives'),
                    'av_percentage': vt_percent
                }
        return response.status_code

    def FSBChck(self, fsb_api):
        """Checks Hybrid Analysis for info for a given file hash."""
        url = 'https://www.hybrid-analysis.com/api/v2/search/hash'
        headers = {'api-key': fsb_api, 'user-agent': 'Falcon'}
        data = {'hash': self.hash}
        response = post(url, headers=headers, data=data)
        if response.status_code == 200:
            if len(response.json()) > 0:
                self.fsb_r_code = 1
                self.fsb_results = {
                    'verdict': response.json()[0].get('verdict'),
                    'm_family': response.json()[0].get('vx_family')
                }
            else:
                self.fsb_r_code = 0
        return response.status_code
