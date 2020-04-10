from email.mime.text import MIMEText
from socket import gethostbyname
from re import search
from os.path import exists
from hashlib import sha256
from smtplib import SMTP
from urllib.error import URLError, HTTPError
from urllib.request import urlopen


def mail_send(mail_sender, mail_recipients, subject, mail_server, mail_body):
    """Simple function to send mail."""
    # Defining mail properties.
    msg = MIMEText(mail_body)
    msg['Subject'] = subject
    msg['From'] = mail_sender
    msg['To'] = mail_recipients
    # Obtaining IP address of SMTP server host name.  If using an IP
    # address, omit the gethostbyname function.
    s = SMTP(gethostbyname(mail_server), '25')
    # Sending the mail.
    s.sendmail(mail_sender, mail_recipients, msg.as_string())


def testURL(url):
    """Tests if connectivity to a URL is successful or not."""
    input_test = search(r'(^https:|^http:)(.+)', url)
    if not input_test.group(1):
        print(r'URL provided does not begin with http(s).')
        exit(1)
    try:
        test = urlopen(url)
        if test.getcode() == 200:
            print('The connection to %s was successful.' % (url))
    except HTTPError as herror:
        print('Unable to connect to %s.\nHTTP Status Code: %s\n' +
              'Reason: %s') % (url, herror.code, herror.reason)
    except URLError as uerror:
        print('Unable to connect to %s\nReason: %s\n' % (url, uerror.reason))


def hash_file(filename):
    """Takes a file and hashes the contents."""
    try:
        if exists(filename):
            hashed_file = open(filename, 'r+b')
        else:
            raise IOError
    except IOError:
        print('The file specified does not exist.  Aborting.')
        exit(1)
    file_hash = sha256(hashed_file.read()).hexdigest()
    return file_hash
