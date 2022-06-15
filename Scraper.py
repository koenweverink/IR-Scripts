import re
import smtplib
from email.message import EmailMessage
from urllib.request import urlopen
from bs4 import BeautifulSoup

item_url = "https://egregornews.com/page/"
search_key = "customerName"

for i in range(1, 31):
    r = urlopen(item_url + str(i))
    soup = BeautifulSoup(r, 'html.parser')

    for x in (soup.find_all(string=re.compile(search_key, flags=re.I))):
        print("Page: " + str(i) + ". Found!")
        s = smtplib.SMTP(host='smtp.office365.com', port=587)
        s.starttls()
        s.login("notification@di-cert.org", "password")
        msg = EmailMessage()
        message = "\nThe name of the client has been found on page {0}. Click here for details: {1}{2}".format(str(i), item_url, str(i))
        msg.set_content(message)
        msg['From'] = "notification@di-cert.org"
        recipients = ["koenweverink@digital-investigation.nl"]
        msg['To'] = ", ".join(recipients)
        msg['Subject'] = "Client found on Site"
        s.send_message(msg)
        del msg

    else:
        print("Page: " + str(i) + ". Not found")
