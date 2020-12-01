# mail-attac - Cracking encrypted Mail Attachements Passwords based on the mailtext

On the mailserver a service filters for the mailtext and encrypted archive files.

From the mailtext a wordlist is extracted and a hash is generated from the paswort protected archive file.

Then the hash of the archive file will be compared to the wordlists hash values trying to crack the password.

The idea is to prevent Social Engineering attacks with encrypted malicous archive files which aren't detected by other services. 

## State of Development

This project is still in development and isn't bug free nor fully working. Feel free to test and
please report any issues or ideas.

## Used Third-Party Services

-   [Mail-in-a-Box](https://github.com/mail-in-a-box/mailinabox) for a quick and simple setup
-   [Rspamd](https://github.com/rspamd/rspamd) as spamfilter to call an external service from
-   [olefy](https://github.com/HeinleinSupport/olefy) as architecture for our own service listening on the TCP port
-   [wwwordlist](https://github.com/Zarcolio/wwwordlist) to generate a wordlist from the mailtext
-   [zip2john](https://github.com/openwall/john/blob/bleeding-jumbo/src/zip2john.c) to generate the hash from the encrypted archive file
-   [johntheripper](https://github.com/openwall/john) to crack the password with the wordlist


## How it works

In `rspamd/local.d/external_services.conf` we define the mime filtering and the TCP socket that olefy listens on.

When the MTA (in our case Mail-in-a-Box uses Postfix) sends mail and smtp data over the milter protocol to the rspamd proxy, the data is transmitted to our service that analyzes the data.

If the data is the mail body (plain/html) wwwordlist will generate a wordlist, if the data is the encrypted archive file the service will call zip2john to generate the hash and try to crack the password by calling johntheripper with the hash and wordlist.

If the password is cracked successfully the service returns the decrypted Archive File to rspamd which can analyze it on malware. If it's not decrypted the mail will be rated as spam or receive a warning for the user. 

# Default Installation



## Install Python3 oletools and python-magic

## Install mail-attac

-   clone or download this repo
-   **add the user and group olefy** or edit olefy.service to use any other existing user/group
-   edit olefy.conf to fit your needs
    --> **The paths fit for Debian style systems and maybe not yours**

-   copy olefy.py daemon file to /usr/local/bin
-   copy olefy.conf to /etc
-   copy the systemd service file olefy.service to /etc/systemd/system
-   enable and unmask the Service
~~
systemctl daemon-reload
systemctl unmask olefy.service
systemctl enable olefy.service
~~

# Extended Installation


# Settings

# Debugging

# Monitoring

# License

MIT-License
