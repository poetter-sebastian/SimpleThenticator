# Security Policy

According to [RFC6238](https://tools.ietf.org/html/rfc6238) never send the QR code, recovery code, or other credentials over unsecured connections.
Get protection against bruteforce and TOTP guessing. 
Use recommended key lengths, key storage options, and algorithm (like hash-algorithm) according [BSI-Guide](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf?__blob=publicationFile&v=6). 

## Supported Versions

I support fixing security issues in the following releases:

| Version | Supported          |
|---------| ------------------ |
| 1.*     | :white_check_mark: |

## Reporting a Vulnerability

Do the following
* Check the issue-board if the vulnerability is already known.
* Prepare a post describing the vulnerability, and the possible exploits.
* Get a fix/patch prepared (if you know how I could fix it).
* Prominently feature the problem in the release announcement.
