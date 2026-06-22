# Privacy Policy for Download Sentinel

**Last Updated:** June 17, 2026

## Introduction

Download Sentinel is committed to protecting your privacy. This Privacy Policy explains what information the extension processes and how it is used.

## Information We Collect

Download Sentinel does **not** collect, store, transmit, or share any personal information about users.

Specifically, Download Sentinel does **not**:

* Collect personally identifiable information (PII)
* Track user activity or browsing behavior
* Store or transmit browsing history
* Collect website content viewed by users
* Create user profiles or analytics data

## How Download Sentinel Works

The extension monitors download events for executable and archive file types in order to help identify potentially malicious downloads.

When a download is initiated, Download Sentinel checks whether the download's domain is included on a predefined whitelist.

When is **not** on the whiteliste, it checks whether the (sanitized) domain is resolved by Quad9 (not blacklsited) and determines its age at RDAP.

When the user has entered his personal free VT API key. Download Sentinel sends the **download URL only** to VirusTotal for reputation analysis. 

### Important Notice

Download Sentinel **does not** upload, transmit, or share:

* The downloaded file itself
* The contents of the downloaded file
* Any personal data
* Any browsing history
* Any information about websites visited other than the specific download URL being checked

## Third-Party Services

- Download Sentinal checks whether Quad9 resolves the domain in download-URL, when it does it also checks the domain age at RDAP
- When an VT API key is entered, the download URL is submitted for analysis to Virus Toal
- The processing of the API call is subject to those third-party own privacy practices and terms of service.
- Quad9 is known for its robust privacy policy, RDAP also has a solid privacy policy (aggregates user agents, domains checked and IPv4 or IPv6 without storing your public IP)
- Virus Total purpose is to share malware signals, this is the reason why only the download-URL reputation is checked (and not the download itself)!

## Data Storage

Download Sentinel does not store any user data on external servers. Any extension settings or whitelist configurations are stored locally within the user's browser.

## Changes to This Privacy Policy

This Privacy Policy may be updated from time to time. Any changes will be reflected by updating the "Last Updated" date at the top of this document.

## Contact

If you have questions about this Privacy Policy or Download Sentinel, please contact the extension developer.
