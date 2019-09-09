#!/usr/bin/python
from coreutils import GetConfig
from requests import get, post


class IPOSINT:
    def __init__(self, ip):
        self.ip = ip
        self.vt_country = str()
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
        data = get(url, params=params).json()
        self.vt_country = data.get('country')
        self.vt_urls = len(data.get('detected_urls'))
        self.vt_refs = len(data.get('detected_referrer_samples'))
        self.vt_comm = len(data.get('detected_communicating_samples'))
        self.vt_dl = len(data.get('detected_downloaded_samples'))

    def TCChck(self):
        url = 'https://www.threatcrowd.org/searchApi/v2/ip/report/'
        params = {'ip': self.ip}
        data = get(url, params=params).json()
        self.tc_mw = len(data.get('hashes'))

    def TMChck(self):
        url = 'https://api.threatminer.org/v2/host.php'
        params = {'q': self.ip, 'rt': '4'}
        data = get(url, params=params).json()
        if data.get('status_message') == 'Results found.':
            self.tm_mw = len(data.get('results'))

    def FSBChck(self, fsb_api):
        url = 'https://www.hybrid-analysis.com/api/v2/search/terms'
        headers = {'api-key': fsb_api, 'user-agent': 'Falcon'}
        data = {'host': self.ip}
        response = post(url, headers=headers, data=data)
        self.fsb_mw = response.json().get('count')

    def TBLChck(self):
        url = 'https://talosintelligence.com/documents/ip-blacklist'
        response = get(url)
        for entry in response.text.split('\n'):
            if self.ip == entry:
                self.tbl_status = 'Blacklisted IP'
            else:
                self.tbl_stauts = 'Non-blacklisted IP'


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

    def VTChck(self, vt_api):
        url = 'https://www.virustotal.com/vtapi/v2/domain/report'
        params = {'apikey': vt_api, 'domain': self.domain}
        data = get(url, params=params).json()
        if data.get('response_code') == 1:
            self.vt_mw_dl = len(data.get('detected_downloaded_samples'))
            self.vt_cats = data.get('categories')
            self.vt_subd = data.get('subdomains')
            self.vt_durls = len(data.get('detected_urls'))
        elif data.get('reponse_code') == 0:
            pass

    def TCChck(self):
        url = 'https://www.threatcrowd.org/searchApi/v2/domain/report/'
        params = {'domain': self.domain}
        data = get(url, params=parmas).json()
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


config = GetConfig('config.cnf')
vt_api_key = config.VTAPI()
fsb_api_key = config.FSBAPI()
