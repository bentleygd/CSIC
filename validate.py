#!/usr/bin/py
from re import match


def validateIP(IP):
    """Takes a string input and returns true if it is a valid IP."""
    valid_ip = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    if match(valid_ip, IP):
        octets = IP.split('.')
        if (int(octets[0]) <= 223 and
            int(octets[1]) <= 255 and
            int(octets[2]) <= 255 and
            int(octets[3]) <= 254
            ):
            return True
        else:
            return False
    else:
        return False


def validateDN(domain_name):
    """Takes a string input and returns true if it is a valid DNS name."""
    # Checking domain name maximum length for RFC 1035 compliance.
    if not len(domain_name) > 255:
        # Checking label legnth for RFC 1035 compliance.
        labels = domain_name.split('.')
        for label in labels[0:len(labels) - 1]:
            print label
            if not len(label) > 63:
                # Checking label composition for RFC 1035 compliance.
                valid_label = r'^[a-zA-Z0-9]+[a-zA-Z0-9-]*[a-zA-Z0-9]$'
                for label in labels:
                    if not match(valid_label, label):
                        return False
            else:
                return False
        return True
    else:
        return False


def validateURL(url):
    """Takes a string input and returns true if it looks like a valid URL."""
    # Checking for recommend maximum length.
    if not len(url) > 2048:
        if not match(r'https:|http:', url):
            print 'URL is not a HTTP scheme.'
            return False
        return True
    else:
        print 'URL lenght exceeds browser maximum length.'
        return False
