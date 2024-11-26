"""
This module retrieves crowd sourced threat intelligence data from
multiple sources via API calls.

Classes:
IPOSINT - Retrieves crowd sourced threat intelligence data about IP addresses.
DomainOSINT - Retrieves crowd sourced threat intelligence data about domain
names.
URLOSINT - Retrieves crowd sourced threat intelligence data about URLs.
FileOSINT - Retrieves crowd sourced threat intelligence data about files.
OSINTBlock - Generated block lists based on gathered CSINT data.
"""
from logging import getLogger

from requests import get, post
from requests.exceptions import Timeout, HTTPError, SSLError

from libs.validate import validateIP


class IPOSINT:
    def __init__(self, ip):
        """An IP address OSINT retrieving ojbect.
        Retrieves OSINT information concerning a given IP address from
        numerous sources.  This is done to empower both information
        security analysts and non-infosec personnel to be able to make
        more informed decisions about a given threat.

        Required Input:
        ip - str(), the IP address to evaluate.

        Instance variables:
        ip - the provided IP address during class instantiation.
        vt_results - results from VirusTotal for the IP..
        vt_response - The response code received from VirusTotal.
        fsb_mw - Falcon SandBox malwre count for the IP.
        tbl_status - Talos block list results for the IP.
        uh_results - URLHaus results for the IP.
        adb_results - AbuseIPDB results for the IP.
        otx_results - OTX results for the IP.
        log - Logging call.

        Methods:
        VTChck - Checks VirusTotal for info for a given IP address.
        FSBChck - Checks Falcon Sandbox (hybrid-analysis) for info for
        a given IP.
        TBLChck - Checks to see if an IP is on the Talos block list.
        UHChck - Checks URLHaus for info for a given IP.
        AIDBChck - Checks the AbuseIP database for a given IP.
        OTXCheck - Retrieves data from AlienVault OTX for a given IP."""
        self.ip = ip
        self.vt_results = dict()
        self.vt_response = int()
        self.fsb_mw = int()
        self.tbl_status = str()
        self.uh_results = dict()
        self.adb_results = list()
        self.otx_results = dict()
        self.log = getLogger('csic')

    def VTChck(self, vt_api):
        """Checks VirusTotal for info for a given IP address.

        Required Input:
        vt_api - str(), A VirusTotal API key.

        Outputs:
        vt_results - dict(), A dictionary containg the information
        retrieved from VirusTotal.

        Returns:
        response.status_code - int(), the HTTP response code returned
        by VirusTotal."""
        url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        params = {'apikey': vt_api, 'ip': self.ip}
        response = get(url, params=params, timeout=5)
        if response.status_code == 200:
            self.log.info(
                'Succesfully retrieved data from VirusTotal for %s', self.ip
            )
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
        else:
            self.log.error(
                'Unable to retrieve info from VirusTotal.  The HTTP ' +
                'response code is %d.', response.status_code)
        return response.status_code

    def FSBChck(self, fsb_api):
        """Checks hybrid-analysis for info for a given IP.

        Required Input:
        fsb_api - The hybrid-analysis API key.

        Outputs:
        fsb_mw - The total count of related malware samples found by
        hybrid analysis.

        Returns:
        response.status_code - The HTTP response returned by Hybrid
        Analysis."""
        url = 'https://www.hybrid-analysis.com/api/v2/search/terms'
        headers = {'api-key': fsb_api, 'user-agent': 'Falcon'}
        data = {'host': self.ip}
        try:
            response = post(url, headers=headers, data=data, timeout=5)
            if response.status_code == 200:
                self.log.info(
                    'Successfully retrieved data from hybrid-analysis ' +
                    'for %s', self.ip
                )
                self.fsb_mw = response.json().get('count')
            else:
                self.log.error(
                    'Error when retrieving data from FSB for %s. ' +
                    'The HTTP response code is %s',
                    (self.ip, response.status_code)
                )
            status_code = 200
        except Timeout:
            self.log.error('Connection to Falcon Sandbox timed out.')
            status_code = 408
        except SSLError:
            self.log.exception('SSL error when connecting to Falcon Sandbox')
            status_code = 495
        return status_code

    def TBLChck(self):
        """Checks to see if an IP is on the Talos block list.

        Outputs:
        tbl_status - Whether or not a given IP address is on the Talos
        block list.

        Returns:
        response.status_code - The HTTP response code returned by the
        Talos website."""
        url = 'https://talosintelligence.com/documents/ip-blacklist'
        response = get(url, timeout=5)
        data = response.text.split('\n')
        if self.ip in data:
            self.tbl_status = 'block listed IP'
        else:
            self.tbl_status = 'Non-block listed IP'
        if response.status_code == 200:
            self.log.info('Successfully retrieved Talos IP black list.')
        else:
            self.log.error('Unable to retrieve Talos black list from Cisco.')
        return response.status_code

    def UHChck(self):
        """Checks URLHaus for info for a given IP.

        Outputs:
        uh_results - A dictionary containing info about a given IP
        address on URLHaus.

        Returns:
        query_status - The status code returned by the URLHause API."""
        url = 'https://urlhaus-api.abuse.ch/v1/host/'
        data = {'host': self.ip}
        response = post(url, data=data, timeout=5).json()
        if response.get('query_status') == 'ok':
            self.log.info(
                'Successfully retrieved data from URLHaus for %s', self.ip
            )
            uh_bl = response.get('blacklists')
            self.uh_results = {
                'mw_count': response.get('url_count'),
                'surbl': uh_bl.get('surbl'),
                'shbl': uh_bl.get('spamhaus_dbl'),
                'ref_url': uh_bl.get('urlhaus_reference')
            }
        else:
            self.log.error(
                'Error occurred when retrieving data from URLHaus for %s .',
                self.ip
                )
        return response.get('query_status')

    def AIDBCheck(self, aid_key):
        """Checks the Abuse IP database for info for a given IP.

        Required Input:
        aid_key - str(), The API key for the Abuse IP database.

        Outputs:
        adb_results - dict(), A dictionary containing info about a
        given IP address from the Abuse IP database.

        Returns:
        response.status_code - int(), The HTTP response code returned
        by Abuse IP DB.

        Exceptions:
        HTTPError - Occurs when the called enpdoint returns a non-200
        response."""
        url = 'https://api.abuseipdb.com/api/v2/check'
        params = {
            'ipAddress': self.ip,
            'MaxAgeInDays': '30'
        }
        headers = {'Accept': 'application/json', 'Key': aid_key}
        response = get(url, headers=headers, params=params, timeout=5)
        try:
            response.raise_for_status
        except HTTPError:
            self.log.exception(
                '%d response received from the AIDB', response.status_code
            )
        data = response.json()['data']
        self.adb_results = {
           'report_count': data['totalReports'],
           'confidence_score': data['abuseConfidenceScore']
        }
        self.log.info('Retrieved abuse IP DB info for %s', self.ip)
        return response.status_code

    def OTXCheck(self, otx_key):
        """Retrieves the reputation data for a given IP address.

        Required Input:
        otx_key - str(), The API key for AlienVault OTX.

        Outputs:
        otx_results - list(), A list containing the OTX reputation data
        from AlienVault OTX.

        Returns:
        response.status_code - int(), The HTTP response code returned by
        the AlienVault OTX API.

        Exceptions:
        HTTPError - Occurs when the called enpdoint returns a non-200
        response."""
        # Setting up OTX request for OTX repuptation data.
        host = 'https://otx.alienvault.com'
        url = '/api/v1/indicators/IPv4/' + self.ip + '/general'
        headers = {'X-OTX-API-KEY': otx_key}
        response = get(host + url, headers=headers, timeout=5)
        # Checking to see if the request was successful.
        try:
            response.raise_for_status
        except HTTPError:
            self.log.exception(
                '%d response received from OTX', response.status_code
            )
        response_data = response.json()
        if 'country_name' in response_data:
            self.otx_results = {
                'country': response_data['country_name'],
                'pulse_count': response_data['pulse_info']['count'],
                'reputation': response_data['reputation']
            }
        else:
            self.otx_results = {
                'pulse_count': response_data['pulse_info']['count'],
                'reputation': response_data['reputation']
            }
        return response.status_code


class DomainOSINT:
    def __init__(self, domain_name):
        """A domain name OSINT retrieving ojbect.

        Required Input:
        domain_name - The domain name to evaluate.

        Instances variables:
        domain - The domain name password as an argument to the
        instantiation of the DomainOSINT object.
        vt_response - The VirusTotal response code.
        vt_results - The results returned by VirusTotal.
        fsb_mw - The count of associated malware samples on Hybrid
        Analysis.
        fsb_ts_avg - The average threat score returned by Hybrid Analysis.
        uh_results - The results returned by URLHaus.
        otx_results - Associated malware data from AlienVault OTX.
        log - Logging call.

        Methods:
        VTChck - Checks VirusTotal for info for a given domain.
        FSBChck - Checks hybrid analysis for info for a given domain.
        UHChck - Checks URLhaus for info for a given domain.
        OTXChck - Retrieves AlienVault OTX for reputation data."""
        self.domain = domain_name
        self.vt_response = int()
        self.vt_results = dict()
        self.fsb_mw = int()
        self.fsb_ts_avg = int()
        self.uh_results = dict()
        self.otx_results = dict()
        self.log = getLogger('csic')

    def VTChck(self, vt_api):
        """Checks VirusTotal for info for a given domain.

        Required Input:
        vt_api - str(), The VirusTotal API key.

        Outputs:
        self.vt_results - dict(), A dictionary containing relevant threat
        data about a given domain name.

        Returns:
        response.status_code - int(), The HTTP status code returned by
        the VT API."""
        url = 'https://www.virustotal.com/vtapi/v2/domain/report'
        params = {'apikey': vt_api, 'domain': self.domain}
        response = get(url, params=params, timeout=5)
        if response.status_code == 200:
            self.log.info(
                'Successfully retrieved data from VirusTotal ' +
                'for %s', self.domain
            )
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
        else:
            self.log.error(
                'Unable to retrieve data for %s from VirusTotal.  The HTTP ' +
                'response code is %d', (self.domain, response.status_code)
            )
        return response.status_code

    def FSBChck(self, fsb_api):
        """Checks hybrid analysis for info for a given domain.

        Required Input:
        fsb_api - str(), The Falcon SandBox API key.

        Outputs:
        self.fsb_ts_avg - int(), The average threatscore for a given
        domain name.

        Returns:
        response.status_code - int(), The HTTP response code."""
        url = 'https://www.hybrid-analysis.com/api/v2/search/terms'
        headers = {'api-key': fsb_api, 'user-agent': 'Falcon'}
        data = {'domain': self.domain}
        try:
            response = post(url, headers=headers, data=data, timeout=5)
            if response.status_code == 200:
                self.log.info(
                    'Successfully retrieved data from hybrid analysis for ' +
                    '%s', self.domain
                )
                self.fsb_mw = response.json().get('count')
                if self.fsb_mw > 0:
                    ts = int()
                    for result in response.json().get('result'):
                        if result.get('threat_score') is not None:
                            ts = ts + result.get('threat_score')
                        else:
                            ts = 0
                    self.fsb_ts_avg = ts / len(response.json().get('result'))
            else:
                self.log.error(
                    'Unable to retrieve data from hybrid-analysis for ' +
                    '%s', self.domain
                )
            status_code = response.status_code
        except Timeout:
            self.log.error('Connection to Falcon Sandbox timed out.')
            status_code = 408
        except SSLError:
            self.log.exception('SSL error when connecting to Falcon Sandbox')
            status_code = 495
        return status_code

    def UHChck(self):
        """Checks URLhaus for info for a given domain.

        Outputs:
        self.uh_results - dict(), The results from URLHaus regarding a
        given domain name.

        Returns:
        respones.get('query_status') - The response status returned by
        the URLHaus API.
        """
        url = 'https://urlhaus-api.abuse.ch/v1/host/'
        data = {'host': self.domain}
        response = post(url, data=data, timeout=5).json()
        if response.get('query_status') == 'ok':
            self.log.info(
                'Successfully retrieved info from URLHaus for ' +
                '%s', self.domain
            )
            uh_bl = response.get('blacklists')
            self.uh_results = {
                'mw_count': response.get('url_count'),
                'surbl': uh_bl.get('surbl'),
                'shbl': uh_bl.get('spamhaus_dbl'),
                'ref_url': uh_bl.get('urlhaus_reference')
            }
        else:
            self.log.error(
                'Unable to retrieve information from URLHaus for ' +
                '%s. The query response is: %s' % (
                    self.domain, response.get('query_status')
                )
            )
        return response.get('query_status')

    def OTXCheck(self, otx_key):
        """Retrieves malware data for a given domain name.

        Required Input:
        otx_key - str(), The API key for AlienVault OTX.

        Outputs:
        otx_results - dict(), A dictionary containing the OTX malware
        data from AlienVault OTX.

        Returns:
        response.status_code - int(), The HTTP response code returned by
        the AlienVault OTX API.

        Exceptions:
        HTTPError - Occurs when the called enpdoint returns a non-200
        response."""
        # Setting up OTX request for OTX general data.
        host = 'https://otx.alienvault.com'
        g_url = '/api/v1/indicators/domain/' + self.domain + '/general'
        headers = {'X-OTX-API-KEY': otx_key}
        g_response = get(host + g_url, headers=headers, timeout=5)
        # Checking to see if the request was successful.
        try:
            g_response.raise_for_status
        except HTTPError:
            self.log.exception(
                '%d response received from OTX', g_response.status_code
            )
        general_data = g_response.json()
        # Retaining the number of OTX pulses associated with the
        # provided DNS name.
        pulse_count = general_data['pulse_info']['count']
        # Setting up OTX rqeuest for domain malware data
        m_url = '/api/v1/indicators/domain/' + self.domain + '/malware'
        m_response = get(host + m_url, headers=headers, timeout=5)
        # Checking to see if response was successful
        try:
            m_response.raise_for_status
        except HTTPError:
            self.log.exception(
                '%d response received from OTX', g_response.status_code
            )
        malware_data = m_response.json()
        # Retaining malware count
        malware_count = malware_data['count']
        # Population OTX results dictionary
        self.otx_results = {
            'pulse_count': pulse_count,
            'malware_count': malware_count
        }
        return g_response.status_code


class URLOSINT:
    def __init__(self, b_url):
        """A URL OSINT retrieving ojbect.

        Required Input:
        b_url - The URL to check.

        Instance variables:
        b_url - The URL to check.
        vt_response - The response code returned by the VirusTotal API.
        vt_results - The results returned by the VirusTotal API.
        fsb_mw - The count of associated malware according to Hybrid Analysis.
        uh_results - The results returned by URLHaus.
        otx_results - The results returned by OTX.
        log - logging call.

        Methods:
        VTChck - Checks VirusTotal for info about a givne URL.
        FSBChck - Checkings FalconSandbox (aka Hybrid Analysis) for
        info about a given URL.
        UHChck - Checks URLHause for info about a given URL.
        OTXChck - Retrieves general info from AlienVault OTX about the
        supplied URL.
        """
        self.b_url = b_url
        self.vt_response = int()
        self.vc_results = dict()
        self.fsb_mw = int()
        self.uh_results = dict()
        self.otx_results = int()
        self.log = getLogger('csic')

    def VTChck(self, vt_api):
        """Checks VirusTotal for info for a given URL.

        Required Input:
        vt_api - str(), The VirusTotal API key.

        Outputs:
        vc_results - dict(), The results returned by the VirusTotal API.

        Returns:
        response.status_code - int(), The response code returned by the
        VirusTotal API."""
        url = 'https://www.virustotal.com/vtapi/v2/url/report'
        params = {'apikey': vt_api, 'resource': self.b_url}
        response = get(url, params=params, timeout=5)
        if response.status_code == 200:
            self.log.info(
                'Successfully retrieved data for %s from VirusTotal',
                self.b_url
            )
            data = response.json()
            self.vt_response = data.get('response_code')
            if self.vt_response == 1:
                self.vc_results = {
                    'scan_date': data.get('scan_date'),
                    'positives': data.get('positives'),
                    'ref_url': data.get('permalink')
                }
        else:
            self.log.error(
                'Unable to retrieve data for %s from VirusTotal. The HTTP ' +
                'response code is %s.', (self.b_url, response.status_code)
            )
        return response.status_code

    def FSBChck(self, fsb_api):
        """Checks hybrid analysis for infor for a given URL.

        Required Input:
        fsb_api - str(), The FalconSandbox API key.

        Outputs:
        fsb_mw - int(), The count of malware samples associated with a
        given URL.

        Returns:
        response.status_cde - int(), The HTTP response code returned by
        the FSB API."""
        url = 'https://www.hybrid-analysis.com/api/v2/search/terms'
        headers = {'api-key': fsb_api, 'user-agent': 'Falcon'}
        data = {'url': self.b_url}
        try:
            response = post(url, headers=headers, data=data, timeout=5)
            if response.status_code == 200:
                self.log.info(
                    'Successfully retrieved info from hybrid analysis for %s',
                    self.b_url
                )
                self.fsb_mw = response.json().get('count')
            else:
                self.log.error(
                    'Unable to retrieve info from hybrid analysis. The HTTP ' +
                    'response code is %r.', (response.status_code)
                )
            status_code = response.status_code
        except Timeout:
            self.log.error('Connection to Falcon Sandbox timed out.')
            status_code = 408
        except SSLError:
            self.log.exception('SSL error when connecting to Falcon Sandbox')
            status_code = 495
        return status_code

    def UHChck(self):
        """Checks URLhaus for info for a given URL.

        Outputs:
        uh_results - dict(), The results returned by the URL Haus API.

        Returns:
        response.get('query_status') - str(), The response status
        returned by the URLHaus API.
        """
        url = 'https://urlhaus-api.abuse.ch/v1/url/'
        data = {'url': self.b_url}
        response = post(url, data=data, timeout=5).json()
        if response.get('query_status') == 'ok':
            self.log.info(
                'Successfully retrieved info for %s from abuse.ch', self.b_url
            )
            uh_bl = response.get('blacklists')
            self.uh_results = {
                'status': response.get('threat'),
                'gsb': uh_bl.get('gsb'),
                'surbl': uh_bl.get('surbl'),
                'shbl': uh_bl.get('spamhaus_dbl'),
                'ref_url': uh_bl.get('urlhaus_reference')
            }
        else:
            self.log.error(
                'Unable to retrieve data from abuse.ch. The query ' +
                'response is %s.', (response.get('query_status'))
            )
        return response.get('query_status')

    def OTXCheck(self, otx_key):
        """Retrieves general OTX data for a given URL.

        Required Input:
        otx_key - str(), The API key for AlienVault OTX.

        Outputs:
        otx_results - int(), The number of OTX pulses that are associated
        with the given URL.

        Returns:
        response.status_code - int(), The HTTP response code returned by
        the AlienVault OTX API.

        Exceptions:
        HTTPError - Occurs when the called enpdoint returns a non-200
        response."""
        # Setting up OTX request for OTX repuptation data.
        host = 'https://otx.alienvault.com'
        url = '/api/v1/indicators/url/' + self.b_url + '/general'
        headers = {'X-OTX-API-KEY': otx_key}
        response = get(host + url, headers=headers, timeout=5)
        # Checking to see if the request was successful.
        try:
            response.raise_for_status
        except HTTPError:
            self.log.exception(
                '%d response received from OTX', response.status_code
            )
        # Getting the pulse count from OTX.
        response_data = response.json()
        self.otx_results = response_data['pulse_info']['count']
        return response.status_code


class FileOSINT:
    def __init__(self, filehash):
        """A file OSINT retrieving ojbect.

        Required Input:
        filehash - The SHA256 hash of a file.

        Instance variables:
        vt_response - The response code returned by the VirusTotal API.
        vt_results - The results returned by VirusTotal for the supplied
        file hash.
        fsb_r_code - The FalconSandbox response code.
        fsb_results - The results returned by FalconSandbox for the
        supplied file hash.
        otx_results - The general data from AlienVault OTX for the
        supplied file hash.
        log - Logging call.

        Methods:
        VTChck - Checks VirusTotal for info for the supplied file hash.
        FSBChck - Checks FalconSandbox for info for the supplied file
        hash.
        OTXChck - Retrieves the AlienVault OTX data for the supplied
        file hsah."""
        self.hash = filehash
        self.vt_response = int()
        self.vt_results = dict()
        self.fsb_r_code = int()
        self.fsb_results = dict()
        self.otx_results = dict()
        self.log = getLogger('csic')

    def VTChck(self, vt_api):
        """Checks VirusTotal for info for a given file hash.

        Required Input:
        vt_api - The VirusTotal API key.

        Outputs:
        vt_results - The results returned by the VirusTotal API
        regrading a given file hash.

        Returns:
        response.status_code - The HTTP response returned by the Virus
        Total API."""
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        params = {'apikey': vt_api, 'resource': self.hash}
        response = get(url, params=params, timeout=5)
        if response.status_code == 200:
            self.log.info(
                'Successfully retrieved info from VT for file hash: %s',
                self.hash
            )
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
        else:
            self.log.error(
                'Unable to retrieve info from VT for %s', self.hash
            )
        return response.status_code

    def FSBChck(self, fsb_api):
        """Checks Hybrid Analysis for info for a given file hash.

        Required Input:
        fsb_api -  The Falcon Sandbox API key.

        Outputs:
        fsb_results - The results returned by the FalconSandbox API
        regarding a given file hash

        Returns:
        response.status_code - The HTTP response code returned by the
        Falcon Sandbox API."""
        url = 'https://www.hybrid-analysis.com/api/v2/search/hash'
        headers = {'api-key': fsb_api, 'user-agent': 'Falcon'}
        data = {'hash': self.hash}
        response = post(url, headers=headers, data=data, timeout=5)
        try:
            if response.status_code == 200:
                self.log.info(
                    'Successfully retrieved info from hybrid analysis for '
                    'hash: %s', self.hash
                )
                if len(response.json()) > 0:
                    self.fsb_r_code = 1
                    self.fsb_results = {
                        'verdict': response.json()[0].get('verdict'),
                        'm_family': response.json()[0].get('vx_family')
                    }
                else:
                    self.fsb_r_code = 0
            else:
                self.log.error(
                    'Unable to retrieve file info from hybrid analysis for %s',
                    self.hash
                )
            status_code = response.status_code
        except Timeout:
            self.log.error('Connection to Falcon Sandbox timed out.')
            status_code = 408
        except SSLError:
            self.log.exception('SSL error when connecting to Falcon Sandbox')
            status_code = 495
        return status_code

    def OTXCheck(self, otx_key):
        """Retrieves general OTX data for the supplied file hash.

        Required Input:
        otx_key - str(), The API key for AlienVault OTX.

        Outputs:
        otx_results - list(), A list containing the general data from
        AlienVault OTX about the supplied URL.

        Returns:
        response.status_code - int(), The HTTP response code returned by
        the AlienVault OTX API.

        Exceptions:
        HTTPError - Occurs when the called enpdoint returns a non-200
        response."""
        # Setting up OTX request for OTX repuptation data.
        host = 'https://otx.alienvault.com'
        url = '/api/v1/indicators/file/' + self.hash + '/general'
        headers = {'X-OTX-API-KEY': otx_key}
        response = get(host + url, headers=headers, timeout=5)
        # Checking to see if the request was successful.
        try:
            response.raise_for_status
        except HTTPError:
            self.log.exception(
                '%d response received from OTX', response.status_code
            )
        response_data = response.json()
        # Parsing response data
        p_count = response_data['pulse_info']['count']
        m_families = []
        m_names = []
        # Getting the malware families for each pulse, parsing through
        # the results and making a list of unique family names only.
        for pulse in response_data['pulse_info']['pulses']:
            m_families.append(pulse['malware_families'])
            for m_family in m_families:
                # Chekcing to see if there are any associated malware
                # families.  If there are, get them.  Otherwise do
                # nothing.
                if len(m_family) > 0:
                    for _name in m_family:
                        m_names.append(_name['display_name'])
        # If there are any malware families associated with the given
        # hash, make them into a unique set.  Otherwise, set the value
        # of family_set to None.
        if len(m_names) > 0:
            family_set = str(set(m_names)).strip('{}')
        else:
            family_set = None
        self.otx_results = {
            'p_count': p_count,
            'm_families': family_set
        }
        return response.status_code


class OSINTBlock():
    def __init__(self):
        """Creates a OSINTBlock object.
        This object utlizes a number of methods to create a list of
        actionable IOCs so that system administrators can proactively
        block known bad IOCs to reduce the amount of noise that may
        be observed at the boundary.  List of IOCs are stored as
        instance variables for ease of reference and updating.  All
        calls via requests return the HTTP status code so that error
        handling can be performed on the script that calls this
        module.

        Instance variables:
        et_ch - The list of compromised hosts from Emerging Threts.
        ssl_bl - The SSL BL from abuse.ch of known botnet C2 hosts.
        tbl - Cisco Talos' block list.
        bl_de - Blocklist.de's blocklist that is updated every 48
        hours.
        nt_ssh_bl - Nothink.org's SSH brute force source block list.
        adb_bl - Abuse IP Database's block list.
        ip_block_list - A combined list of unique IPs to block.
        self.log - Logging call.

        Methods:
        get_et_ch - Retrieves the compromised host list from emerging
        threats.
        get_abuse_sslbl - Retrieves the known botnet C2 list from
        abuse.ch.
        get_talos_list - Retrieves the black list from Talos.
        get_blde_list - Retriees the black list from blocklist.de
        get_nt_ssh_bl - Retrieves the black list of ssh brute force
        servers from nothink.org
        get_adb_bl - Retrieves the black list from the Abuse IP
        database.
        generate_block_list - Combines all blocklists and generates
        a list of unique IPs to block."""
        self.et_ch = []
        self.ssl_bl = []
        self.tbl = []
        self.bl_de = []
        self.nt_ssh_bl = []
        self.adb_bl = []
        self.ip_block_list = []
        self.log = getLogger('auto_ip_block')

    def get_et_ch(self):
        """Retrieves list of compromised hosts from emerging threats.

        Outputs:
        self.et_ch - A list of IP addresses of compromised hosts that
        are spewing evil.

        Returns:
        response.status_code - The HTTP staus code of the request made
        to emerging threats."""
        url = (
            'https://rules.emergingthreats.net' +
            '/blockrules/compromised-ips.txt'
        )
        try:
            response = get(url, timeout=5)
            data = response.text
            for entry in data.split('\n'):
                if not entry.startswith('#') and validateIP(entry):
                    self.et_ch.append(entry.strip('\n') + '/32')
            self.log.info(
                'Succesfully retrieved compromised IP list from ET.'
            )
            self.log.debug(
                '%d IPs are in the compromised IP list from ET.',
                len(self.et_ch)
            )
        except Exception:
            self.log.exception(
                'Unable to retrieve compromised IP list from ET.'
            )
        return response.status_code

    def get_ssl_bl(self):
        """Retrieves the known botnet C2 list from abuse.ch

        Outputs:
        self.ssl_bl - A list of IP addresses that are known botnet C2
        servers.

        Returns:
        response.status_code - The HTTP staus code of the request made
        to emerging threats."""
        url = 'https://sslbl.abuse.ch/blacklist/sslipblacklist.txt'
        try:
            response = get(url, timeout=5)
            data = response.text
            for entry in data.split('\r\n'):
                if not entry.startswith('#') and validateIP(entry):
                    self.ssl_bl.append(entry + '/32')
            self.log.info(
                'Successfully retrieved known botnet C2 list from abuse.ch'
            )
            self.log.debug(
                '%d hosts are indicated as botnet C2 hosts by abuse.ch',
                len(self.ssl_bl)
            )
        except Exception:
            self.log.exception(
                'Unable to retrive botnet C2 list from URLHaus.'
            )
        return response.status_code

    def get_talos_list(self):
        """Retrieves the IP block list from Cisco Talos

        Outputs:
        self.ssl_bl - A list of IP addresses that Talos has determined
        are persona non gratta.

        Returns:
        response.status_code - The HTTP staus code of the request made
        to emerging threats."""
        url = 'https://talosintelligence.com/documents/ip-blacklist'
        try:
            response = get(url, timeout=5)
            data = response.text
            for entry in data.split('\n'):
                if not entry.startswith('#') and validateIP(entry):
                    self.tbl.append(entry + '/32')
            self.log.info('Succesfully retrieved Talos black list.')
            self.log.debug(
                '%d hosts are in the Talos black list', len(self.tbl)
            )
        except Exception:
            self.log.exception('Unable to retrieve block list from Talos.')
        return response.status_code

    def get_blde_list(self):
        """Retrieves the block list from blocklist.de

        Outputs:
        self.bl_de - Blocklist.de's blocklist that is updated every 48
        hours.

        Returns:
        response.status_code - The HTTP response returned from
        blocklist.de"""
        url = 'https://lists.blocklist.de/lists/all.txt'
        try:
            response = get(url, timeout=5)
            data = response.text
            for entry in data.split('\n'):
                if not entry.startswith('#') and validateIP(entry):
                    self.bl_de.append(entry + '/32')
            self.log.info(
                'Succesfully retrieved the ban list from blocklist.de'
            )
            self.log.debug(
                '%d hosts are in the blocklist.de ban list.', len(self.bl_de)
            )
        except Exception:
            self.log.exception(
                'Unable to retrieve the ban list from blocklist.de'
            )
        return response.status_code

    def get_nt_ssh_bl(self):
        """Retrieves the SSH block list from nothink.org

        Outputs:
        self.nt_ssh_bl - Nothink.org's SSH brute force source block
        list.

        Returns:
        response.status_code - The HTTP response returned from
        nothink.org"""
        url = (
            r'http://www.nothink.org/honeypots/' +
            r'honeypot_ssh_blacklist_2019.txt'
        )
        try:
            response = get(url, timeout=5)
            data = response.text
            for entry in data.split('\n'):
                if not entry.startswith('#') and validateIP(entry):
                    self.nt_ssh_bl.append(entry + '/32')
            self.log.info(
                'Successfully retrieved list of known ssh brute force ' +
                'servers from nothink.org.'
            )
            self.log.debug(
                '%d hosts are in the ssh_brute force list from nothink.org',
                len(self.nt_ssh_bl)
            )
        except Exception:
            self.log.exception(
                'Unable to retrieve list of ssh brute force servers from ' +
                'nothink.org'
            )
        return response.status_code

    def get_adb_bl(self, api_key):
        """Retrieves the black list from the Abuse IP DB.

        Required Input:
        api_key - An Abuse IP DB API key.

        Returns:
        response.status_code - The HTTP code returned by the block list
        API endpoint.

        Exceptions:
        HTTPError - Occurs when a non-200 response is generated by the
        Abuse IP DB block list endpoint.
        Timeout - Occurs when the request to the endpoint times out."""
        url = 'https://api.abuseipdb.com/api/v2/blacklist'
        headers = {'Accept': 'text/plain', 'Key': api_key}
        params = {'limit': '10000'}
        try:
            response = get(url, headers=headers, params=params, timeout=10)
            response.raise_for_status
        except Timeout:
            self.log.exception('Timeout occurred connecting to %s', url)
        except HTTPError:
            self.log.exception('Non-200 response received from %s', url)
        for ip in response.text.split('\n'):
            if validateIP(ip):
                self.adb_bl.append(ip + '/32')
        return response.status_code

    def generate_block_list(self):
        """Combines all blocklists and generates a list of unique IPs
        to block.

        Outputs:
        self.ip_block_list - A list of unique IPs to block."""
        staging_list = []
        unique_list = []
        osint_lists = [
            self.nt_ssh_bl,
            self.ssl_bl,
            self.tbl,
            self.bl_de,
            self.et_ch,
            self.adb_bl
        ]
        for _list in osint_lists:
            for item in _list:
                staging_list.append(item)
        for item in staging_list:
            if item not in unique_list:
                unique_list.append(item)
        for unique_item in unique_list:
            if unique_item in self.nt_ssh_bl:
                write_item = unique_item + ' #ABL Nothink SSH Ban list.'
            if unique_item in self.ssl_bl:
                write_item = unique_item + ' #ABL URLHaus Botnet C2.'
            if unique_item in self.tbl:
                write_item = unique_item + ' #ABL Talos block list IP.'
            if unique_item in self.bl_de:
                write_item = unique_item + ' #ABL Blocklist.de Ban list.'
            if unique_item in self.et_ch:
                write_item = unique_item + ' #ABL ET Compromised Host.'
            if unique_item in self.adb_bl:
                write_item = unique_item + ' #ABL Abuse IP DB block list IP'
            self.ip_block_list.append(write_item)
        self.log.info(
            '%d IPs are in the consolidated block list.',
            len(self.ip_block_list)
        )
        return self.ip_block_list
