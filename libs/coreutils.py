from email.mime.text import MIMEText
from socket import gethostbyname
from os.path import exists
from hashlib import sha256
from smtplib import SMTP


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
