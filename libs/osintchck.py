from requests import get, post
from logging import getLogger
from requests.exceptions import Timeout, HTTPError

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
        tc_mw - Threat crowd malware count for the IP.
        tm_mw - Threat miner malware count for the IP.
        fsb_mw - Falcon SandBox malwre count for the IP.
        tbl_status - Talos block list results for the IP.
        uh_results - URLHaus results for the IP.
        adb_results - AbuseIPDB results for the IP.
        log - Logging call.

        Methods:
        VTChck - Checks VirusTotal for info for a given IP address.
        TCChck - Checks ThreatCrowd for info for a given IP.
        TMChck - Checks ThreatMiner for info for a given IP.
        FSBChck - Checks Falcon Sandbox (hybrid-analysis) for info for
        a given IP.
        TBLChck - Checks to see if an IP is on the Talos block list.
        UHChck - Checks URLHaus for info for a given IP.
        AIDBChck - Checks the AbuseIP database for a given IP."""
        self.ip = ip
        self.vt_results = dict()
        self.vt_response = int()
        self.tc_mw = int()
        self.tm_mw = int()
        self.fsb_mw = int()
        self.tbl_status = str()
        self.uh_results = dict()
        self.adb_results = list()
        self.log = getLogger('csic')

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
        try:
            response = get(url, params=params, timeout=5)
        except Timeout:
            self.log.exception(
                'Timeout occurred during connection to ThreatCrowd'
                )
            status_code = 500
            return status_code
        except Exception:
            self.log.exception('Exception occured, please investigate')
            status_code = 500
            return status_code
        try:
            response.raise_for_status
        except HTTPError:
            self.log.exception(
                '%d error code from ThreatCrowd' % response.status_code
            )
            status_code = 500
            return status_code
        if response.json() is not None:
            data = response.json()
        else:
            status_code = 500
            return status_code
        if data.get('response_code') == '1':
            self.tc_mw = len(data.get('hashes'))
            status_code = 200
            self.log.info(
                'Successfully retrieved data for %s from ' +
                'ThreatCrowd.', self.ip
            )
        else:
            status_code = 404
            self.log.info('No data preset on ThreatCrowd for %s', self.ip)
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
            self.log.exception(
                'Error retrieving data from ThreatMiner for %s. The ' +
                'response code is %s', (self.ip, status_code)
            )
            return status_code
        except Timeout:
            status_code = 408
            self.log.exception(
                'Timeout in operation retrieving data from ThreatMiner for ' +
                '%s.', self.ip
            )
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
            self.log.info(
                'Successfully retrieved data from hybrid-analysis ' +
                'for %s', self.ip
            )
            self.fsb_mw = response.json().get('count')
        else:
            self.log.error(
                'Error when retrieving data from hybrid analysis for %s. ' +
                'The HTTP response code is %s',
                (self.ip, response.status_code)
            )
        return response.status_code

    def TBLChck(self):
        """Checks to see if an IP is on the Talos block list.

        Outputs:
        tbl_status - Whether or not a given IP address is on the Talos
        block list.
        response.status_code - The HTTP response code returned by the
        Talos website."""
        url = 'https://talosintelligence.com/documents/ip-blacklist'
        response = get(url)
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
        query_status - The status returned by the URLHause API."""
        url = 'https://urlhaus-api.abuse.ch/v1/host/'
        data = {'host': self.ip}
        response = post(url, data=data).json()
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

        Exceptions:
        HTTPError - Occurs when the called enpdoint returns a non-200
        response."""
        url = 'https://api.abuseipdb.com/api/v2/check'
        params = {
            'ipAddress': self.ip,
            'MaxAgeInDays': '30'
        }
        headers = {'Accept': 'application/json', 'Key': aid_key}
        response = get(url, headers=headers, params=params)
        try:
            response.raise_for_status
        except HTTPError:
            self.log.exception(
                '%d response received from the AIDB' % response.status_code
            )
        data = response.json()['data']
        self.adb_results = {
           'report_count': data['totalReports'],
           'confidence_score': data['abuseConfidenceScore']
        }
        self.log.info('Retrieved abuse IP DB info for %s' % self.ip)
        return response.status_code


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
        log - Logging call.

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
        self.log = getLogger('csic')

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
            self.log.info(
                'Successfully retrieved data from ThreatCrowd for ' +
                '%s', self.domain
            )
            self.tc_rc = len(data.get('resolutions'))
            for entry in data.get('resolutions'):
                self.tc_ips.append({'ip_address': entry.get('ip_address'),
                                   'r_time': entry.get('last_resolved')})
            status_code = 200
        else:
            self.log.error(
                'Unable to retrieve data from ThreatCrowd for %s', self.domain
            )
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
                self.log.info(
                    'Successfully retrieved data for %s from ThreatMiner',
                    self.domain
                )
                self.tm_mw = len(data.get('results'))
        except HTTPError:
            status_code = response.status_code
            self.log.exception(
                'Error retrieving data from ThreatMiner for %s. The ' +
                'response code is %d', (self.domain, status_code)
            )
            return status_code
        except Timeout:
            self.log.exception(
                'Timeout occured retrieving data from Threat Miner for ' +
                '%s', self.domain
            )
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
        log - logging call.

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
        self.log = getLogger('csic')

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
            self.log.info(
                'Successfully retrieved info from hybrid analysis for %s',
                self.b_url
            )
            self.fsb_mw = response.json().get('count')
        else:
            self.log.error(
                'Unable to retrieve info from hybrid analysis for %s. The ' +
                'HTTP response code is %s.' % (
                    self.b_url, response.status_code
                )
            )
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
                'Unable to retrieve data for %s from abuse.ch. The query ' +
                'response is %s.' % (self.b_url, response.get('query_status'))
            )
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
        log - Logging call.

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
        self.log = getLogger('csic')

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
        response.status_code - The HTTP staus code of the request made
        to emerging threats."""
        url = (
            'https://rules.emergingthreats.net' +
            '/blockrules/compromised-ips.txt'
        )
        try:
            response = get(url)
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
        response.status_code - The HTTP staus code of the request made
        to emerging threats."""
        url = 'https://sslbl.abuse.ch/blacklist/sslipblacklist.txt'
        try:
            response = get(url)
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
        response.status_code - The HTTP staus code of the request made
        to emerging threats."""
        url = 'https://talosintelligence.com/documents/ip-blacklist'
        try:
            response = get(url)
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
        response.status_code - The HTTP response returned from
        blocklist.de"""
        url = 'https://lists.blocklist.de/lists/all.txt'
        try:
            response = get(url)
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
        response.status_code - The HTTP response returned from
        nothink.org"""
        url = (
            r'http://www.nothink.org/honeypots/' +
            r'honeypot_ssh_blacklist_2019.txt'
        )
        try:
            response = get(url)
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

        Output:
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
            self.log.exception('Timeout occurred connecting to', url)
        except HTTPError:
            self.log.exception('Non-200 response received from', url)
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
