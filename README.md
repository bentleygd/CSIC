# CSIC
Python scripts that automate checking different crowd-source threat intelligence feeds to determine if something is evil.

[![Known Vulnerabilities](https://snyk.io/test/github/bentleygd/CSIC/badge.svg?targetFile=requirements.txt)](https://snyk.io/test/github/bentleygd/CSIC?targetFile=requirements.txt)![Lint](https://github.com/bentleygd/CSIC/workflows/Lint/badge.svg)

# Motivation
The purpose of this project is to reduce the amount of time that is used during an investigation on whether or not something is "bad".  The scripts can also be used to empower lower tier support teams (i.e., help desk personnel) with a quick and efficient way of determing if something is "bad" when they communicate with users or higher tier support personnel.

# Features
The CSIC scripts supports checking several reputable threat intelligence sources to provide aggregated results.  A summary of sources for each type of indicator is included below.

**IP Address**
- [Virus Total](https://www.virustotal.com/)
- [Falcon Sandbox](https://www.hybrid-analysis.com/)
- [AlienVault OTX](https://otx.alienvault.com/)
- [Abuse IP Database](https://www.abuseipdb.com/)
- [Cisco Talos Black List](https://talosintelligence.com/reputation_center/)
- [URLHaus](https://urlhaus.abuse.ch/)

**Domain Names**
- [Virus Total](https://www.virustotal.com/)
- [Falcon Sandbox](https://www.hybrid-analysis.com/)
- [AlienVault OTX](https://otx.alienvault.com/)
- [URLHaus](https://urlhaus.abuse.ch/)

**URLs**
- [Virus Total](https://www.virustotal.com/)
- [Falcon Sandbox](https://www.hybrid-analysis.com/)
- [AlienVault OTX](https://otx.alienvault.com/)
- [URLHaus](https://urlhaus.abuse.ch/)

**Files**
- [Virus Total](https://www.virustotal.com/)
- [Falcon Sandbox](https://www.hybrid-analysis.com/)
- [AlienVault OTX](https://otx.alienvault.com/)

# Install
I have a side effort to get these scripts working in a standalone executable for Windows.  I have not met with much success with py2exe.  So for now, you have to clone the repo.

`$ git clone https://github.com/bentleygd/CSIC.git`

# Usage
The default help option is self-explanatory.

> python csic_cli.py -h
> usage: csic_cli.py [-h] [-I] [-D] [-U] [-F] indicator
> 
> Open Threat Intel checker.
>
> positional arguments:
>  indicator   Indicator to check for.
>
> optional arguments:<br>
>  -h, --help  show this help message and exit<br>
>  -I, --ip    Check for IP address info.<br>
>  -D, --dns   Check for DNS info.<br>
>  -U, --url   Check for URL info.<br>
>  -F, --file  Check for File info.<br>

# Example Configuration
```python
# This configuration uses configparser
[API]
vt = viurs_total_api_key
fsb = hybrid_analysis_api_key
aipdb = abuse_ip_db_api_key
otx = alienvault_otx_api_key

[mail]
server = somewhere.example.com
rcpts = someone@example.com
sender = bot@example.com

[block]
path = path_to_file
```

# Documentation
See DOCs.md for more detailed documentation.