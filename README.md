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
-   [johntheripper](https://github.com/openwall/john) to crack the password with the wordlist


## How it works

In `rspamd/local.d/external_services.conf` we define the mime filtering and the TCP socket that olefy listens on.

When the MTA (in our case Mail-in-a-Box uses Postfix) sends mail and smtp data over the milter protocol to the Rspamd proxy, the data is transmitted to our service that analyzes the data.

If the data is the mail body (plain/html) wwwordlist will generate a wordlist, if the data is the encrypted archive file the service will call an archive-function from john to generate the hash and try to crack the password by calling johntheripper with the hash and wordlist.

If the password is cracked successfully the service could then return the decrypted archive file to Rspamd which could analyze it on malware. This last step is not implemented yet as we are clueless on how to pass the decrypted files back to Rspamd so we left it up to the user to decide what to do after the password has been cracked.

Demo:
[![asciicast](https://asciinema.org/a/muxhHlRDHWk9QOdEvZxN3UF6H.svg)](https://asciinema.org/a/muxhHlRDHWk9QOdEvZxN3UF6H)

For further information and installation instructions visit the [wiki](https://github.com/DanielWidmayer/mail-attac/wiki)

# License

MIT-License
