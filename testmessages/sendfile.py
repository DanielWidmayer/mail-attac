#!/usr/bin/env python

import smtplib
import socket
from sys import argv
import pwd
import os
from os.path import basename
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import COMMASPACE, formatdate


def send_mail(send_from, send_to, subject, text, files=None):
    assert isinstance(send_to, list)

    msg = MIMEMultipart()
    msg['From'] = send_from
    msg['To'] = COMMASPACE.join(send_to)
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject

    msg.attach(MIMEText(text))

    for f in files or []:
        with open(f, 'rb') as fil:
            part = MIMEApplication(
                    fil.read(),
                    Name=basename(f)
            )
            part['Content-Disposition'] = 'attachment; filename="%s"' % basename(f)
            msg.attach(part)

        with open('mail.eml', 'w') as f:
            f.write(msg.as_string())

user = pwd.getpwuid(os.getuid()).pw_name
host = socket.gethostname()

send_mail('%s@%s' % (user, host),
        ['me@pwcracker.email'],
        argv[1],
        argv[2],
        argv[3:]
    )
