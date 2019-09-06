#!/usr/bin/python
from coreutils import GetConfig
from requests import get


class IPOSINTSummary:
    def __init__(self, ip):
        self.ip = ip
        self.vt_country = str()
        self.vt_urls = int()
        self.vt_refs = int()
        self.vt_comm = int()
        self.vt_dl = int()
        self.tc_mw = int()
        self.tm_mw = int()

    def VTChck(vt_api):
        url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        params = {'apikey': vt_api, 'ip': self.ip}
        response = get(url, params=params)
        data = response.json()
        for d_key in data:
            if d_key == 'country':
                self.vt_country = data.get('country')
            if d_key == 'detected_urls':
                vt_urls = len(data.get('detected_urls'))
            if d_key == 'detected_referrer_samples':
                vt_refs = len(data.get('detected_referrer_samples'))
            if d_key == 'detected_communicating_samples':
                vt_comm = len(data.get('detected_communicating_samples'))
            if d_key == 'detected_donwloaded_samples':
                vt_dl = len(data.get('detected_downloaded_samples'))

    def TCChck():
        url = 'https://www.threatcrowd.org/searchApi/v2/ip/report/'
        params = {'ip': self.ip}
        response = get(url, params=params)
        data = response.json()
        tc_mw = len(data.get('hashes'))

    def TMChck():
        url = 'https://api.threatminer.org/v2/host.php'
        params = {'q': self.ip, 'rt': '4'}
        response = get(url, params=params)
        data = response.json()
        if data.get('status_message') == 'Results found.':
            tm_mw = len(data.get('results'))


# config = GetConfig('config.cnf')
# vt_api = config.VTAPI()
