# IP Address OSINT Class Documentation

This Python class is designed to retrieve Open Source Intelligence (OSINT) information for a given IP address. It collects data from various sources to help information security analysts and non-technical users make informed decisions regarding potential threats.

## Class: `IP_OSINT`

### Constructor: `__init__(self, ip)`
Initializes the IP_OSINT object with the provided IP address and sets up instance variables for storing the results from various OSINT sources.

#### Required Input:
- `ip` (`str`): The IP address to evaluate.

#### Instance Variables:
- `ip` (`str`): The provided IP address during class instantiation.
- `vt_results` (`dict`): Results from VirusTotal for the IP.
- `vt_response` (`int`): The response code received from VirusTotal.
- `fsb_mw` (`int`): Falcon Sandbox malware count for the IP.
- `tbl_status` (`str`): Talos block list status for the IP.
- `uh_results` (`dict`): URLHaus results for the IP.
- `adb_results` (`list`): AbuseIPDB results for the IP.
- `otx_results` (`dict`): OTX results for the IP.
- `tor_exit` (`list`): A list of TOR exit nodes.
- `log` (`Logger`): Logger instance for logging API responses.

---
## Methods

### `VTChck(self, vt_api)`
Checks VirusTotal for information regarding the provided IP address.

#### Required Input:
- `vt_api` (`str`): A valid VirusTotal API key.

#### Outputs:
- `vt_results` (`dict`): A dictionary containing information retrieved from VirusTotal, including owner, country, detected URLs, and downloads.
- `response.status_code` (`int`): The HTTP response code returned by VirusTotal.

---

### `FSBChck(self, fsb_api)`
Checks Falcon Sandbox (Hybrid Analysis) for malware information regarding the provided IP address.

#### Required Input:
- `fsb_api` (`str`): A valid Falcon Sandbox API key.

#### Outputs:
- `fsb_mw` (`int`): The total count of related malware samples found by Hybrid Analysis.
- `response.status_code` (`int`): The HTTP response code returned by Hybrid Analysis.

#### Exceptions:
- `Timeout`: Raised if the request times out.
- `SSLError`: Raised for SSL connection issues.

---

### `TBLChck(self)`
Checks whether the IP address is on the Talos block list.

#### Outputs:
- `tbl_status` (`str`): Whether the IP is listed as blocked or not.
- `response.status_code` (`int`): The HTTP response code returned by the Talos website.

---

### `UHChck(self)`
Checks URLHaus for information about the provided IP address.

#### Outputs:
- `uh_results` (`dict`): A dictionary containing information about the IP address on URLHaus, including malware count and blacklisting status.
- `query_status` (`str`): The query status returned by the URLHaus API.

---

### `AIDBCheck(self, aid_key)`
Checks the AbuseIPDB for information about the provided IP address.

#### Required Input:
- `aid_key` (`str`): A valid API key for AbuseIPDB.

#### Outputs:
- `adb_results` (`dict`): A dictionary containing abuse-related data about the IP address.
- `response.status_code` (`int`): The HTTP response code returned by AbuseIPDB.

#### Exceptions:
- `HTTPError`: Raised if the HTTP response status is not 200.

---

### `OTXCheck(self, otx_key)`
Retrieves reputation data for the provided IP address from AlienVault OTX.

#### Required Input:
- `otx_key` (`str`): A valid API key for AlienVault OTX.

#### Outputs:
- `otx_results` (`dict`): A dictionary containing reputation data, such as country, pulse count, and reputation score.
- `response.status_code` (`int`): The HTTP response code returned by AlienVault OTX.

#### Exceptions:
- `HTTPError`: Raised if the HTTP response status is not 200.

---

### `TORCheck(self)`
Retrieves the list of TOR exit nodes from TOR and checks to see if an IP address is an exit node.

#### Required Input:
- **None**

#### Outputs:
- `tor_exit` (`list`): A list of TOR exit nodes.

#### Returns:
- `tor_status` (`bool`): Returns True if *self.ip* is in self.tor_exit.

#### Exceptions:
- `Exception`: Raised if there is a problem with connecting to TOR.

---

## Example Usage:

```python
# Instantiate the IP_OSINT class with a given IP address
ip_osint = IP_OSINT("8.8.8.8")

# Check VirusTotal
vt_api = "your_virustotal_api_key"
ip_osint.VTChck(vt_api)

# Check Falcon Sandbox (Hybrid-Analysis)
fsb_api = "your_falcon_sandbox_api_key"
ip_osint.FSBChck(fsb_api)

# Check Talos Blocklist
ip_osint.TBLChck()

# Check URLHaus
ip_osint.UHChck()

# Check AbuseIPDB
aid_key = "your_abuseipdb_api_key"
ip_osint.AIDBCheck(aid_key)

# Check AlienVault OTX
otx_key = "your_otx_api_key"
ip_osint.OTXCheck(otx_key)

# Check to see self.ip is a TOR exit node
exit_node_check = ip_osint.TORCheck()
if exit_node_check is True:
  print('IP address is an exit node')
else:
  print('IP address is not an exit node')
```

# DomainOSINT Class Documentation

The `DomainOSINT` class is designed to retrieve OSINT (Open Source Intelligence) data for a given domain name. It interacts with multiple external services (**VirusTotal**, **Hybrid-Analysis (Falcon Sandbox)**, **URLHaus**, and **AlienVault OTX**) to collect relevant threat and reputation data about the specified domain.

## Class: `DomainOSINT`

### Constructor: `__init__(self, domain_name)`
Initializes the `DomainOSINT` object with the provided domain name.

#### Required Input:
- `domain_name` (`str`): The domain name to evaluate.

#### Instance Variables:
- `domain` (`str`): The domain name passed to the constructor.
- `vt_response` (`int`): The response code returned by VirusTotal.
- `vt_results` (`dict`): A dictionary containing the results retrieved from VirusTotal.
- `fsb_mw` (`int`): The count of associated malware samples from Hybrid-Analysis.
- `fsb_ts_avg` (`int`): The average threat score from Hybrid-Analysis.
- `uh_results` (`dict`): A dictionary containing results from URLHaus.
- `otx_results` (`dict`): A dictionary containing data from AlienVault OTX.
- `log` (`Logger`): A logging call used to log information and errors.

---
## Methods

### `VTChck(self, vt_api)`
Checks VirusTotal for information on the specified domain.

##### Required Input:
- `vt_api` (`str`): The VirusTotal API key.

##### Outputs:
- `vt_results` (`dict`): A dictionary containing relevant threat data about the given domain name.

##### Returns:
- `response.status_code` (`int`): The HTTP status code returned by the VirusTotal API.

---

### `FSBChck(self, fsb_api)`
Checks Hybrid-Analysis (Falcon Sandbox) for information about the given domain.

#### Required Input:
- fsb_api (str): The Falcon Sandbox API key.

#### Outputs:
- fsb_ts_avg (int): The average threat score for the given domain.

#### Returns:
- response.status_code (int): The HTTP status code returned by Hybrid-Analysis.

---

### `UHChck(self)`
Checks URLHaus for information about the given domain.

#### Outputs:
- uh_results (dict): A dictionary containing results from URLHaus regarding the domain.

#### Returns:
- response.get('query_status') (str): The query status returned by the URLHaus API.

---

### `OTXCheck(self, otx_key)`
Retrieves malware data for the given domain from AlienVault OTX.

#### Required Input:
- otx_key (str): The API key for AlienVault OTX.

#### Outputs:
- otx_results (dict): A dictionary containing OTX-related malware data for the domain.

#### Returns:
- response.status_code (int): The HTTP status code returned by the AlienVault OTX API.

#### Exceptions:
- HTTPError: Raised when the endpoint returns a non-200 HTTP response.

---

### Example Usage
```python
# Example of using the DomainOSINT class

# Instantiate the DomainOSINT object with a domain name
domain_osint = DomainOSINT(domain_name="example.com")

# Check VirusTotal data
vt_status = domain_osint.VTChck(vt_api="your_virus_total_api_key")
print(domain_osint.vt_results)

# Check Hybrid-Analysis data
fsb_status = domain_osint.FSBChck(fsb_api="your_falcon_sandbox_api_key")
print(domain_osint.fsb_ts_avg)

# Check URLHaus data
uh_status = domain_osint.UHChck()
print(domain_osint.uh_results)

# Check AlienVault OTX data
otx_status = domain_osint.OTXCheck(otx_key="your_otx_api_key")
print(domain_osint.otx_results)
```

# URLOSINT Class Documentation

## Overview
The `URLOSINT` class is designed to retrieve Open Source Intelligence (OSINT) related to a URL from multiple sources: **VirusTotal**, **Hybrid Analysis (Falcon Sandbox)**, **URLHaus**, and **AlienVault OTX**. It provides methods to query these services and extract relevant information about a given URL.

## Class: `URLOSINT`

### Constructor: `__init__(self, b_url)`
Initializes the `URLOSINT` object with the given URL.

#### Parameters:
- `b_url` (str): The URL to check.

#### Instance Variables:
- `b_url` (str): The URL to check.
- `vt_response` (int): The response code returned by the VirusTotal API.
- `vc_results` (dict): The results returned by the VirusTotal API.
- `fsb_mw` (int): The count of associated malware according to Hybrid Analysis.
- `uh_results` (dict): The results returned by URLHaus.
- `otx_results` (int): The results returned by OTX (AlienVault).
- `log` (logging.Logger): Logger instance for logging information and errors.

---

## Methods

### `VTChck(self, vt_api)`
Checks VirusTotal for information about a given URL.

#### Parameters:
- `vt_api` (str): The VirusTotal API key.

#### Outputs:
- `vc_results` (dict): A dictionary containing VirusTotal scan date, positives, and permalink.
  
#### Returns:
- `response.status_code` (int): The HTTP response code returned by the VirusTotal API.

---

### `FSBChck(self, fsb_api)`
Checks Hybrid Analysis (FalconSandbox) for information about a given URL.

#### Parameters:
- `fsb_api` (str): The FalconSandbox API key.

#### Outputs:
- `fsb_mw` (int): The count of malware samples associated with the given URL.

#### Returns:
- `response.status_code` (int): The HTTP response code returned by the Hybrid Analysis API.

---

### `UHChck(self)`
Checks URLHaus for information about a given URL.

#### Outputs:
- `uh_results` (dict): A dictionary containing threat status, blacklists, and reference URLs.

#### Returns:
- `response.get('query_status')` (str): The query status returned by the URLHaus API.

---

### `OTXCheck(self, otx_key)`
Retrieves general reputation data for a given URL from AlienVault OTX.

#### Parameters:
- `otx_key` (str): The API key for AlienVault OTX.

#### Outputs:
- `otx_results` (int): The number of OTX pulses associated with the given URL.

#### Returns:
- `response.status_code` (int): The HTTP response code returned by the AlienVault OTX API.

#### Exceptions:
- `HTTPError`: Raised if the HTTP request to OTX returns a non-200 status code.

---

## Example Usage

```python
# Example initialization and usage of the URLOSINT class

# Create an URLOSINT object with the URL to check
url_check = URLOSINT('http://example.com')

# Check VirusTotal for information
vt_api = 'your_virus_total_api_key'
status_code = url_check.VTChck(vt_api)
print(f"VirusTotal response code: {status_code}")

# Check Hybrid Analysis for associated malware
fsb_api = 'your_falcon_sandbox_api_key'
status_code = url_check.FSBChck(fsb_api)
print(f"Hybrid Analysis response code: {status_code}")

# Check URLHaus for threat information
uh_status = url_check.UHChck()
print(f"URLHaus query status: {uh_status}")

# Check AlienVault OTX for general information
otx_key = 'your_otx_api_key'
status_code = url_check.OTXCheck(otx_key)
print(f"OTX response code: {status_code}")
```

# FileOSINT Class Documentation

## Overview
The `FileOSINT` class is designed to retrieve Open Source Intelligence (OSINT) for a file based on its SHA256 hash. It queries several external services to gather information about the file, including **VirusTotal**, **Hybrid Analysis (FalconSandbox)**, and **AlienVault OTX**.

This class provides methods to check file reputation and other related data from these sources.

## Class: `FileOSINT`

### Constructor: `__init__(self, filehash)`
Initializes the `FileOSINT` object with the provided SHA256 hash.

#### Parameters:
- `filehash` (str): The SHA256 hash of the file.

#### Instance Variables:
- `hash` (str): The SHA256 hash of the file.
- `vt_response` (int): The response code returned by the VirusTotal API.
- `vt_results` (dict): The results returned by VirusTotal for the supplied file hash.
- `fsb_r_code` (int): The FalconSandbox response code.
- `fsb_results` (dict): The results returned by FalconSandbox for the supplied file hash.
- `otx_results` (dict): The general data from AlienVault OTX for the supplied file hash.
- `log` (logging.Logger): Logger instance for logging information and errors.

---

## Methods

### `VTChck(self, vt_api)`
Checks VirusTotal for information related to the provided file hash.

#### Parameters:
- `vt_api` (str): The API key for VirusTotal.

#### Outputs:
- `vt_results` (dict): The results returned by the VirusTotal API for the given file hash. Includes:
  - `'av_detect'`: Number of antivirus engines that detected the file.
  - `'av_percentage'`: The percentage of antivirus engines that detected the file.
  - `'ref_url'`: The permalink to the VirusTotal report.

#### Returns:
- `response.status_code` (int): The HTTP status code returned by the VirusTotal API.

---

### `FSBChck(self, fsb_api)`
Checks FalconSandbox (Hybrid Analysis) for information related to the provided file hash.

#### Parameters:
- `fsb_api` (str): The API key for FalconSandbox.

#### Outputs:
- `fsb_results` (dict): The results returned by the FalconSandbox API regarding the file hash. Includes:
  - `'verdict'`: The verdict of the file analysis (e.g., malicious, suspicious).
  - `'m_family'`: The malware family associated with the file, if applicable.

#### Returns:
- `response.status_code` (int): The HTTP status code returned by FalconSandbox API.

---

#### Exception Handling:
- **Timeout**: If the request times out, a status code of `408` is returned.
- **SSLError**: If there is an SSL error, a status code of `495` is returned.

---

### `OTXCheck(self, otx_key)`
Retrieves general data from AlienVault OTX for the supplied file hash.

#### Parameters:
- `otx_key` (str): The API key for AlienVault OTX.

#### Outputs:
- `otx_results` (dict): A dictionary containing:
  - `'p_count'`: The pulse count, representing the number of OTX pulses associated with the file hash.
  - `'m_families'`: A set of unique malware family names associated with the file.

#### Returns:
- `response.status_code` (int): The HTTP status code returned by the AlienVault OTX API.

#### Exceptions:
- **HTTPError**: Raised if the response from OTX is not successful (non-200 status code).

---

## Example Usage

```python
# Initialize the FileOSINT object with the file's SHA256 hash
file_osint = FileOSINT('your_file_sha256_hash')

# Check VirusTotal for file information
vt_api = 'your_virus_total_api_key'
status_code = file_osint.VTChck(vt_api)
print(f"VirusTotal status code: {status_code}")
print(f"VirusTotal Results: {file_osint.vt_results}")

# Check FalconSandbox (Hybrid Analysis) for file analysis
fsb_api = 'your_falcon_sandbox_api_key'
status_code = file_osint.FSBChck(fsb_api)
print(f"FalconSandbox status code: {status_code}")
print(f"FalconSandbox Results: {file_osint.fsb_results}")

# Retrieve general data from AlienVault OTX
otx_key = 'your_otx_api_key'
status_code = file_osint.OTXCheck(otx_key)
print(f"OTX status code: {status_code}")
print(f"OTX Results: {file_osint.otx_results}")
```
