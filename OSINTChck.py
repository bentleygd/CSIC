#!/usr/bin/python
from coreutils import GetConfig
from requests import get, post


class IPOSINT:
    def __init__(self, ip):
        self.ip = ip
        self.vt_country = str()
        self.vt_owner = str()
        self.vt_urls = int()
        self.vt_refs = int()
        self.vt_comm = int()
        self.vt_dl = int()
        self.tc_mw = int()
        self.tm_mw = int()
        self.fsb_mw = int()
        self.tbl_status = str()

    def VTChck(self, vt_api):
        url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        params = {'apikey': vt_api, 'ip': self.ip}
        response = get(url, params=params)
        if response.status_code == 200:
            data = response.json()
            self.vt_owner = data.get('as_owner')
            self.vt_country = data.get('country')
            self.vt_urls = len(data.get('detected_urls'))
            self.vt_refs = len(data.get('detected_referrer_samples'))
            self.vt_comm = len(data.get('detected_communicating_samples'))
            self.vt_dl = len(data.get('detected_downloaded_samples'))
            return response.status_code
        else:
            return response.status_code

    def TCChck(self):
        url = 'https://www.threatcrowd.org/searchApi/v2/ip/report/'
        params = {'ip': self.ip}
        data = get(url, params=params).json()
        if data.get('response_code') == '1':
            self.tc_mw = len(data.get('hashes'))
            status_code = 200
            return status_code
        else:
            status_code = 404
            return status_code

    def TMChck(self):
        url = 'https://api.threatminer.org/v2/host.php'
        params = {'q': self.ip, 'rt': '4'}
        data = get(url, params=params).json()
        if data.get('status_code') == '200':
            self.tm_mw = len(data.get('results'))
            return int(data.get('status_code'))
        else:
            return int(data.get('status_code'))

    def FSBChck(self, fsb_api):
        url = 'https://www.hybrid-analysis.com/api/v2/search/terms'
        headers = {'api-key': fsb_api, 'user-agent': 'Falcon'}
        data = {'host': self.ip}
        response = post(url, headers=headers, data=data)
        if response.status_code == 200:
            self.fsb_mw = response.json().get('count')
            return response.status_code
        else:
            return response.status_code

    def TBLChck(self):
        url = 'https://talosintelligence.com/documents/ip-blacklist'
        try:
            response = get(url)
            for entry in response.text.split('\n'):
                if self.ip == entry:
                    self.tbl_status = 'Blacklisted IP'
                else:
                    self.tbl_status = 'Non-blacklisted IP'
        except ConnectionError:
            print('Unable to retreive Talos Blacklist due to network ' +
                  'connection problems.')
            pass


class DomainOSINT:
    def __init__(self, domain_name):
        self.domain = domain_name
        self.vt_mw_dl = int()
        self.vt_cats = list()
        self.vt_subd = list()
        self.vt_durls = int()
        self.tc_rc = int()
        self.tc_ips = list()
        self.tm_mw = int()
        self.fsb_mw = int()
        self.uh_mw = int()
        self.uh_surbl = str()
        self.uh_shbl = str()

    def VTChck(self, vt_api):
        url = 'https://www.virustotal.com/vtapi/v2/domain/report'
        params = {'apikey': vt_api, 'domain': self.domain}
        response = get(url, params=params)
        if response.status_code == 200:
            data = response.json()
            if data.get('response_code') == 1:
                self.vt_mw_dl = len(data.get('detected_downloaded_samples'))
                self.vt_cats = data.get('categories')
                self.vt_subd = data.get('subdomains')
                self.vt_durls = len(data.get('detected_urls'))
            return response.status_code
        else:
            return response.status_code

    def TCChck(self):
        url = 'https://www.threatcrowd.org/searchApi/v2/domain/report/'
        params = {'domain': self.domain}
        data = get(url, params=params).json()
        self.tc_rc = len(data.get('resolutions'))
        for entry in data.get('resolutions'):
            self.tc_ips.append({'ip_address': entry.get('ip_address'),
                               'r_time': entry.get('last_resolved')})

    def TMChck(self):
        url = 'https://api.threatminer.org/v2/domain.php'
        params = {'q': self.domain, 'rt': '4'}
        data = get(url, params=params).json()
        if data.get('status_message') == 'Results found.':
            self.tm_mw = len(data.get('results'))

    def FSBChck(self, fsb_api):
        url = 'https://www.hybrid-analysis.com/api/v2/search/terms'
        headers = {'api-key': fsb_api, 'user-agent': 'Falcon'}
        data = {'domain': self.domain}
        response = post(url, headers=headers, data=data)
        self.fsb_mw = response.json().get('count')

    def UHChck(self):
        url = 'https://urlhaus-api.abuse.ch/v1/host/'
        data = {'host': self.domain}
        response = post(url, data=data)
        if response.get('query_status') == 'ok':
            self.uh_mw = response.json().get('url_count')
            uh_bl = response.json().get('blacklists')
            self.uh_surbl = uh_bl.get('surbl')
            self.uh_shbl = uh_bl.get('spamhaus_dbl')
        elif response.get('query_status') == 'no_results':
            self.uh_mw = 'no results'
            self.uh_surbl = 'no results'
            self.uh_shbl = 'no results'


class URLOSINT:
    def __init__(self, b_url):
        self.b_url = b_url
        self.vc_sd = str()
        self.vc_sr = int()
        self.fsb_mw = int()
        self.uh_status = str()
        self.uh_gsb = str()
        self.uh_surbl = str()
        self.uh_shbl = str()

    def VTChck(self, vt_api):
        url = 'https://www.virustotal.com/vtapi/v2/url/report'
        params = {'apikey': vt_api, 'resource': self.b_url}
        response = get(url, param=params)
        if response.status_code == 200:
            data = response.json()
            if data.get('response_code') == 1:
                self.vc_sd = data.get('scan_date')
                self.vc_sr = data.get('positives')
            return response.status_code
        else:
            return response.status_code

    def FSBChck(self, fsb_api):
        url = 'https://www.hybrid-analysis.com/api/v2/search/terms'
        headers = {'api-key': fsb_api, 'user-agent': 'Falcon'}
        data = {'url': self.b_url}
        response = post(url, headers=headers, data=data).json()
        self.fsb_mw = response.get('count')

    def UHChck(self):
        url = 'https://urlhaus-api.abuse.ch/v1/url/'
        data = {'url': self.b_url}
        response = post(url, data=data).json()
        if response.get('query_status') == 'ok':
            self.uh_status = response.get('threat')
            uh_bl = response.get('blacklists')
            self.uh_gsb = uh_bl.get('gsb')
            self.uh_surbl = uh_bl.get('surbl')
            self.uh_shbl = uh_bl.get('spamhaus_dbl')
        else:
            self.uh_status = response.get('query_status')


config = GetConfig('config.cnf')
vt_api_key = config.VTAPI()
fsb_api_key = config.FSBAPI()
