from requests import get, post, ReadTimeout, HTTPError


class IPOSINT:
    def __init__(self, ip):
        """An IP address OSINT retrieving ojbect.

        Keyword Arguments:
        ip - str(), the IP address to evaluate.

        Instance variables:
        ip - the IP address passed as a keyword argument.
        vt_results - results from VirusTotal for the IP passed a
        keyword argument.
        vt_response - The response code received from VirusTotal.
        tc_mw - Threat crowd malware count for the IP passed a keyword
        argument.
        tm_mw - Threat miner malware count for the IP passed a keyword
        argument.
        fsb_mw - Falcon SandBox malwre count for the IP passed a
        keyword argument.
        tbl_status - Talos blacklist results for the IP passed a
        keyword argument.
        uh_results - URLHaus results for the IP passed a keyword
        argument.

        Methods:
        VTChck - Checks VirusTotal for info for a given IP address.
        TCChck - Checks ThreatCrowd for info for a given IP.
        TMChck - Checks ThreatMiner for info for a given IP.
        FSBChck - Checks Falcon Sandbox (hybrid-analysis) for info for
        a given IP.
        TBLChck - Checks to see if an IP is on the Talos blacklist.
        UHChck - Checks URLHaus for info for a given IP."""
        self.ip = ip
        self.vt_results = dict()
        self.vt_response = int()
        self.tc_mw = int()
        self.tm_mw = int()
        self.fsb_mw = int()
        self.tbl_status = str()
        self.uh_results = dict()

    def VTChck(self, vt_api):
        """Checks VirusTotal for info for a given IP address.

        Keyword aguments:
        vt_api - A VirusTotal API key.

        Outputs:
        vt_results - dict(), A dictionary containg the information
        retrieved from VirusTotal.
        response.status_code - int(), the HTTP response code returned
        by VirusTotal."""
        url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        params = {'apikey': vt_api, 'ip': self.ip}
        response = get(url, params=params)
        if response.status_code == 200:
            data = response.json()
            self.vt_response = data.get('response_code')
            if self.vt_response == 1:
                if 'detected_downloaded_samples' in data:
                    self.vt_results = {
                        'owner': data.get('as_owner'),
                        'country': data.get('country'),
                        'urls': len(data.get('detected_urls')),
                        'downloads': len(
                            data.get('detected_downloaded_samples')
                        )
                    }
                else:
                    self.vt_results = {
                        'owner': data.get('as_owner'),
                        'country': data.get('country'),
                        'urls': len(data.get('detected_urls'))
                    }
        return response.status_code

    def TCChck(self):
        """Checks ThreatCrowd for info for a given IP.

        Keyword arguments:
        None.

        Outputs:
        tc_mw - The number of malware samples associated with a given
        IP address according to threat crowd.
        status_code - A status code inidcating whether or not data was
        provided for a given IP address."""
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
        """Checks ThreatMiner for info for a given IP.

        Keyword arguments:
        None

        Outputs:
        tm_mw - The number of malware samples associated with a given
        IP address according to threat miner.
        status_code - HTTP response code.

        Raises
        HTTPError - Occurs when there is a non-HTTP 200 respone code.
        ReadTimeout - Occurs when there is a timeout communicating with
        Threat Miner."""
        url = 'https://api.threatminer.org/v2/host.php'
        params = {'q': self.ip, 'rt': '4'}
        try:
            response = get(url, params=params, timeout=3)
            response.raise_for_status()
            data = response.json()
            if (response.status_code == 200 and
                    data.get('status_code') == '200'):
                self.tm_mw = len(data.get('results'))
        except HTTPError:
            status_code = response.status_code
            return status_code
        except ReadTimeout:
            status_code = 408
            return status_code
        return int(data.get('status_code'))

    def FSBChck(self, fsb_api):
        """Checks hybrid-analysis for info for a given IP.

        Keyword arguments:
        fsb_api - The hybrid-analysis API key.

        Outputs:
        fsb_mw - The total count of related malware samples found by
        hybrid analysis.
        response.status_code - The HTTP response returned by Hybrid
        Analysis."""
        url = 'https://www.hybrid-analysis.com/api/v2/search/terms'
        headers = {'api-key': fsb_api, 'user-agent': 'Falcon'}
        data = {'host': self.ip}
        response = post(url, headers=headers, data=data)
        if response.status_code == 200:
            self.fsb_mw = response.json().get('count')
        return response.status_code

    def TBLChck(self):
        """Checks to see if an IP is on the Talos blacklist.

        Outputs:
        tbl_status - Whether or not a given IP address is on the Talos
        blacklist.
        response.status_code - The HTTP response code returned by the
        Talos website."""
        url = 'https://talosintelligence.com/documents/ip-blacklist'
        response = get(url)
        data = response.text.split('\n')
        if self.ip in data:
            self.tbl_status = 'Blacklisted IP'
        else:
            self.tbl_status = 'Non-blacklisted IP'
        return response.status_code

    def UHChck(self):
        """Checks URLHaus for info for a given IP.

        Outputs:
        uh_results - A dictionary containing info about a given IP
        address on URLHaus.
        query_status - The status returned by the URLHause API."""
        url = 'https://urlhaus-api.abuse.ch/v1/host/'
        data = {'host': self.ip}
        response = post(url, data=data).json()
        if response.get('query_status') == 'ok':
            uh_bl = response.get('blacklists')
            self.uh_results = {
                'mw_count': response.get('url_count'),
                'surbl': uh_bl.get('surbl'),
                'shbl': uh_bl.get('spamhaus_dbl'),
                'ref_url': uh_bl.get('urlhaus_reference')
            }
        return response.get('query_status')


class DomainOSINT:
    def __init__(self, domain_name):
        """A domain name OSINT retrieving ojbect.

        Keyword arguments:
        domain_name - The domain name to evaluate.

        Instances variables:
        domain - The domain name password as an argument to the
        instantiation of the DomainOSINT object.
        vt_response - The VirusTotal response code.
        vt_results - The results returned by VirusTotal.
        tc_rc - The ThreatCrowd response code.
        tc_ips - The IPs returned by ThreatCrowd associated with the
        domain name.
        tm_mw - The count of associated malware samples on ThreatMiner.
        fsb_mw - The count of associated malware samples on Hybrid
        Analysis.
        fsb_ts_avg - The average threat score returned by Hybrid Analysis.
        uh_results - The results returned by URLHaus.

        Methods:
        VTChck - Checks VirusTotal for info for a given domain.
        TCChck - Checks ThreatCrowd for info for a given domain.
        TMChck - Checks ThreatMiner for info for a given domain.
        FSBChck - Checks hybrid analysis for info for a given domain.
        UHChck - Checks URLhaus for info for a given domain."""
        self.domain = domain_name
        self.vt_response = int()
        self.vt_results = dict()
        self.tc_rc = int()
        self.tc_ips = list()
        self.tm_mw = int()
        self.fsb_mw = int()
        self.fsb_ts_avg = int()
        self.uh_results = dict()

    def VTChck(self, vt_api):
        """Checks VirusTotal for info for a given domain.

        Keyword arguments:
        vt_api - The VirusTotal API key.

        Outputs:
        vt_results - A dictionary containing relevant threat data
        about a given domain name.
        response.status_code - The HTTP status code returned by the
        VT API."""
        url = 'https://www.virustotal.com/vtapi/v2/domain/report'
        params = {'apikey': vt_api, 'domain': self.domain}
        response = get(url, params=params)
        if response.status_code == 200:
            data = response.json()
            self.vt_response = data.get('response_code')
            if self.vt_response == 1:
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
        """Checks ThreatCrowd for info for a given domain.

        Outputs:
        tc_rc - ThreatCrowd resolution count.
        status_code - The status code indicating whether or not the
        lookup was successful."""
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
        """Checks ThreatMiner for info for a given domain.

        Outputs:
        tm_mw - The count of how many malware samples were associated
        with the domain name.
        status_code - The HTTP response."""
        url = 'https://api.threatminer.org/v2/domain.php'
        params = {'q': self.domain, 'rt': '4'}
        try:
            response = get(url, params=params, timeout=3)
            response.raise_for_status()
            data = response.json()
            if (response.status_code == 200 and
                    data.get('status_code') == '200'):
                self.tm_mw = len(data.get('results'))
        except HTTPError:
            status_code = response.status_code
            return status_code
        except ReadTimeout:
            status_code = 408
            return status_code
        return int(data.get('status_code'))

    def FSBChck(self, fsb_api):
        """Checks hybrid analysis for info for a given domain.

        Keyword arugments:
        fsb_api - The Falcon SandBox API key.

        Outputs:
        fsb_ts_avg - The average threatscore for a given domain name.
        response.status_code - The HTTP response."""
        url = 'https://www.hybrid-analysis.com/api/v2/search/terms'
        headers = {'api-key': fsb_api, 'user-agent': 'Falcon'}
        data = {'domain': self.domain}
        response = post(url, headers=headers, data=data)
        if response.status_code == 200:
            self.fsb_mw = response.json().get('count')
            if self.fsb_mw > 0:
                ts = int()
                for result in response.json().get('result'):
                    ts = ts + result.get('threat_score')
                self.fsb_ts_avg = ts / len(response.json().get('result'))
        return response.status_code

    def UHChck(self):
        """Checks URLhaus for info for a given domain.

        Outputs:
        uh_results - The results from URLHaus regarding a given domain
        name.
        respones.get('query_status') - The response status returned by
        the URLHaus API.
        """
        url = 'https://urlhaus-api.abuse.ch/v1/host/'
        data = {'host': self.domain}
        response = post(url, data=data).json()
        if response.get('query_status') == 'ok':
            uh_bl = response.get('blacklists')
            self.uh_results = {
                'mw_count': response.get('url_count'),
                'surbl': uh_bl.get('surbl'),
                'shbl': uh_bl.get('spamhaus_dbl'),
                'ref_url': uh_bl.get('urlhaus_reference')
            }
        return response.get('query_status')


class URLOSINT:
    def __init__(self, b_url):
        """A domain name OSINT retrieving ojbect.

        Keyword Arguments:
        b_url - The URL to check.

        Instance variables:
        b_url - The URL to check.
        vt_response - The response code returned by the VirusTotal API.
        vt_results - The results returned by the VirusTotal API.
        fsb_mw - The count of associated malware according to Hybrid Analysis.
        uh_results - The results returned by URLHaus.

        Methods:
        VTChck - Checks VirusTotal for info about a givne URL.
        FSBChck - Checkings FalconSandbox (aka Hybrid Analysis) for
        info about a given URL.
        UHChck - Checks URLHause for info about a given URL.
        """
        self.b_url = b_url
        self.vt_response = int()
        self.vc_results = dict()
        self.fsb_mw = int()
        self.uh_results = dict()

    def VTChck(self, vt_api):
        """Checks VirusTotal for info for a given URL.

        Keyword arguments:
        vt_api - The VirusTotal API key.

        Outputs:
        vc_results - The results returned by the VirusTotal API.
        response.status_code - The response code returned by the
        VirusTotal API."""
        url = 'https://www.virustotal.com/vtapi/v2/url/report'
        params = {'apikey': vt_api, 'resource': self.b_url}
        response = get(url, params=params)
        if response.status_code == 200:
            data = response.json()
            self.vt_response = data.get('response_code')
            if self.vt_response == 1:
                self.vc_results = {
                    'scan_date': data.get('scan_date'),
                    'positives': data.get('positives'),
                    'ref_url': data.get('permalink')
                }
        return response.status_code

    def FSBChck(self, fsb_api):
        """Checks hybrid analysis for infor for a given URL.

        Keyword arguments:
        fsb_api - The FalconSandbox API key.

        Outputs:
        fsb_mw - The count of malware samples associated with a given
        URL.
        respons.status_cde - The HTTP response code returned by the
        FSB API."""
        url = 'https://www.hybrid-analysis.com/api/v2/search/terms'
        headers = {'api-key': fsb_api, 'user-agent': 'Falcon'}
        data = {'url': self.b_url}
        response = post(url, headers=headers, data=data)
        if response.status_code == 200:
            self.fsb_mw = response.json().get('count')
        return response.status_code

    def UHChck(self):
        """Checks URLhaus for info for a given URL.

        Outputs:
        uh_results - The results returned by the URL Haus API.
        respones.get('query_status') - The response status returned by
        the URLHaus API.
        """
        url = 'https://urlhaus-api.abuse.ch/v1/url/'
        data = {'url': self.b_url}
        response = post(url, data=data).json()
        if response.get('query_status') == 'ok':
            uh_bl = response.get('blacklists')
            self.uh_results = {
                'status': response.get('threat'),
                'gsb': uh_bl.get('gsb'),
                'surbl': uh_bl.get('surbl'),
                'shbl': uh_bl.get('spamhaus_dbl'),
                'ref_url': uh_bl.get('urlhaus_reference')
            }
        return response.get('query_status')


class FileOSINT:
    def __init__(self, filehash):
        """A file OSINT retrieving ojbect.

        Keyword arguments:
        filehash - The SHA256 hash of a file.

        Instance variables:
        vt_response - The response code returned by the VirusTotal API.
        vt_results - The results returned by VirusTotal regarding a
        given file hash.
        fsb_r_code - The FalconSandbox response code.
        fsb_results - The results returned by FalconSandbox regarding a
        given file hash.

        Methods:
        VTChck - Checks VirusTotal for info regarding a given file
        hash.
        FSBChck - Checks FalconSandbox for info regarding a given file
        hash."""
        self.hash = filehash
        self.vt_response = int()
        self.vt_results = dict()
        self.fsb_r_code = int()
        self.fsb_results = dict()

    def VTChck(self, vt_api):
        """Checks VirusTotal for info for a given file hash.

        Keyword arguments:
        vt_api - The VirusTotal API key.

        Outputs:
        vt_results - The results returned by the VirusTotal API
        regrading a given file hash.
        response.status_code - The HTTP response returned by the Virus
        Total API."""
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': vt_api, 'resource': self.hash}
        response = get(url, params=params)
        if response.status_code == 200:
            data = response.json()
            self.vt_response = data.get('response_code')
            if self.vt_response == 1:
                vt_percent = int(round(
                             float(data.get('positives'))
                             / float(data.get('total')),
                             2) * 100)
                self.vt_results = {
                    'av_detect': data.get('positives'),
                    'av_percentage': vt_percent,
                    'ref_url': data.get('permalink')
                }
        return response.status_code

    def FSBChck(self, fsb_api):
        """Checks Hybrid Analysis for info for a given file hash.

        Keyword arguments:
        fsb_api -  The Falcon Sandbox API key.

        Outputs:
        fsb_results - The results returned by the FalconSandbox API
        regarding a given file hash
        response.status_code - The HTTP response code returned by the
        Falcon Sandbox API."""
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