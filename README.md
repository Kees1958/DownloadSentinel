Warns for potentially harmful downloads.

Chrome webstore: https://chromewebstore.google.com/detail/download-sentinel/ofjlbohlnaihneapmmnhkbllbekdofce

DOWNLOAD SENTINEL

IMPORTANT NOTICE: DOWNLOAD SENTINEL DOES NOT BLOCK THE DOWNLOAD, IN STEAD IT PERFORMS ON-DOWNLOAD AND ON-FILE WRITE CHECKS TO WARN YOU FOR SNEAKY TACTICS WHICH WOULD NOT BE SIGNALED WHEN THE INITIAL DOWNLOAD WAS BLOCKED. AFTER THE DOWNLOAD FINISHES THE RESULTS ARE PRESENTED IN A WARNING POPUP. YOU CAN SUPPRESS THIS WARNING FOR ¨PROBABLY SAFE DOWNLOAD¨ IN THE OPTIONS.

_________________________ Using the extension

1. Click on the Download Sentinal icon and the banner shows the current status of the extension.
<img width="838" height="275" alt="image" src="https://github.com/user-attachments/assets/799ce443-99f7-4c92-88d4-9b4bbcd12c17" />


_________________________ What Download Sentinal does to protect you

Every time you download a file, Download Sentinel quietly runs a set of quick checks. No single check is proof of danger on its own; instead, each one adds or removes a few "trust points," and the final total decides whether the file looks Safe, Questionable, Suspicious, or Malicious.

1. Does anyone else already know this file/site is bad or safe?
Reputation scan (VirusTotal): Checks if security companies around the world have already flagged this exact download link as malicious, and how long it's been known about. A link seen and confirmed clean for weeks is trusted more than one that appeared an hour ago. DNS blocklist check (Quad9): Checks the website's address against known lists of malicious domains — similar to a phone number being flagged as a scam caller.

2. Is the website itself trustworthy?
Domain & website-ending checks: Some website names and endings (like certain unusual .xyz-style suffixes) are used far more often for scams than legitimate ones, so a match lowers trust. How new is the website?: Scam sites are often thrown together and abandoned quickly. A domain registered only days ago is treated with more suspicion than one that's existed for years. Look-alike names: Catches tricks like fake Microsoft/Apple/PayPal-style addresses, confusable letters (e.g. "m1crosoft"), or oddly long chains of sub-addresses designed to fool the eye.

3. Is the file itself hiding something?
File type vs. label mismatch: If a site claims to be sending a photo but is actually sending a program, that mismatch is a red flag. Disguised file endings: Catches tricks like "invoice.pdf.exe", even longer chains like "invoice.pdf.zip.exe" — a program pretending to be a harmless document by hiding its real ending. File swapped along the way: Warns when the file that actually arrives is riskier than what the download link first promised. Raw scripts: Bare scripts are a common way to sneak malicious commands past you. A home user has little to no reason to download scripts. Unusually large files: Very large files can't be fully scanned by reputation services, so they're flagged as "check this yourself before trusting it."

4. Is the connection itself risky?
Unencrypted connections: Downloads sent without the padlock (HTTPS) can be tampered with in transit — including a link that starts secure but drops the padlock partway through. Raw numeric addresses: Legitimate services almost always use a proper website name, not a bare set of numbers as the address. Hidden destination in the link: Some links show a trustworthy-looking name but secretly point somewhere else right after it — this trick is now caught too. Risky hosting: Some free/throwaway hosting platforms are disproportionately used to distribute malware, so files served from them are treated with extra caution.

Open Source: https://github.com/Kees1958/DownloadSentinel

HOW DOES THE WARNING PAGE WORK?

The warning page shows a risk score based on what VirusTotal knows about the download address. The file itself is never sent to VirusTotal, which is better for your privacy and gives a faster result. After checking the results, you can choose to proceed, or to look up the download at VirusTotal (when it is known there), or at Hybrid Analysis for a free scan with Metadefender and Crowdstrike (when it is not known at VirusTotal yet).


<img width="2498" height="880" alt="image" src="https://github.com/user-attachments/assets/f5343e20-90eb-41fe-92ff-a7fee5eb9269" />




_________________________ What you need to set in the OPTIONS 

1. Signup to Virus Total to get a free API key and enter the key (required)
2. Click on the options button to enter your free Virus Total API key (https://www.virustotal.com/gui/join-us)
3. Optionally
   
a) Change the False Positive default setting (standard at medium, change is optional) and suppress probably safe downloads

b) Change the background color of the warning screen, which defaults to Google Safe Browsing (optional)

c) Enter up to 12 domains which are white listed to skip the download check of executables and archives for these websites (optional)
<img width="708" height="967" alt="image" src="https://github.com/user-attachments/assets/ca3b7268-5fd7-426a-9e90-055fb43b8c6a" />



_________________________  PERMISSIONS 

1. Download - because it has to intercept downloads
2. Options UI for pages/options/OptionsPage.html - because the extension has an options page 
3. Storage  - because it saves your Virus Total API key and domain whitelist you enter on the options page
4. Alarms - because it needs to know whether a (small) file downloaded before Virus Total returns results
5. Host permission for   
- www.virustotal.com - because it checks the reputation of the download URL at VTHost permission 
- www.quad9.com      - because it checks whether the domain of the download URL is on Quad9 blacklist
- www.rdap.org        - because it check for the domain age (less 30 days is suspicious) 

_________________________  PRIVACY

It does not monitor nor save or transmit any of the URL's your are visiting. Only the download URL is handled over to Virus Total when it is an executable or compressed file download and NOT on the whitelist. Normal downloads (PDF's word documents, spreadsheets, powerpoints, movies, pictures, etc) are skipped. 

Privacy policy: https://github.com/Kees1958/DownloadSentinel/blob/main/privacy.md)


_________________________ Issues or suggestions

Please post issues or suggestions on https://github.com/Kees1958/DownloadSentinel/issues.



_________________________ License

This project is licensed under the GNU GPL v3.0 - see LICENSE file for details.
