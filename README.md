# CSIChck
Python scripts that automate checking different crowd-source threat intelligence feeds to determine if something is evil.

[![Known Vulnerabilities](https://snyk.io/test/github/bentleygd/CSIC/badge.svg?targetFile=requirements.txt)](https://snyk.io/test/github/bentleygd/CSIC?targetFile=requirements.txt)![Lint and Test](https://github.com/bentleygd/CSIC/workflows/Lint%20and%20Test/badge.svg)[![Total alerts](https://img.shields.io/lgtm/alerts/g/bentleygd/CSIC.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/bentleygd/CSIC/alerts/)[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/bentleygd/CSIC.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/bentleygd/CSIC/context:python)

# Motivation
The purpose of this project is to reduce the amount of time that is used during an investigation on whether or not something is "bad".  The scripts can also be used to empower lower tier support teams (i.e., help desk personnel) with a quick and efficient way of determing if something is "bad" when they communicate with users or higher tier support personnel.

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

# Documentation
See DOCs.md for more detailed documentation.