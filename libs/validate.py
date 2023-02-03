from re import match


def validateIP(IP):
    """Takes a string input and returns true if it is a valid IP."""
    valid_ip = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    if match(valid_ip, IP):
        return True
    else:
        return False


def validateDN(domain_name):
    """Takes a string input and returns true if it is a valid DNS name."""
    # Checking domain name maximum length for RFC 1035 compliance.
    if not len(domain_name) > 255:
        # Checking label legnth for RFC 1035 compliance.
        labels = domain_name.split('.')
        for thing in labels[0:len(labels) - 1]:
            if not len(thing) > 63:
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
