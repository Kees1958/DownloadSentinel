Warns for potentially harmful downloads.

Chrome webstore: https://chromewebstore.google.com/detail/download-sentinel/ofjlbohlnaihneapmmnhkbllbekdofce

DOWNLOAD SENTINEL

IMPORTANT NOTICE: DOWNLOAD SENTINEL DOES NOT BLOCK THE DOWNLOAD, IN STEAD IT PERFORMS ON-DOWNLOAD AND ON-FILE WRITE CHECKS TO WARN YOU FOR SNEAKY TACTICS WHICH WOULD NOT BE SIGNALED WHEN THE INITIAL DOWNLOAD WAS BLOCKED. AFTER THE DOWNLOAD FINISHES THE RESULTS ARE PRESENTED IN A WARNING POPUP. YOU CAN SUPPRESS THIS WARNING FOR ¨PROBABLY SAFE DOWNLOAD¨ IN THE OPTIONS.

_________________________ Why use it?
1. Checks download URL (see explanation below) and provides a risk score of the download
2. Does not use any CPU cycles because it is inactive until something is downloaded (press Shift+Esc and you will see active tabs and service workers, but you won´t see Download Sentinel because it is inactive until something is downloaded).
3. Designed for privacy (click on the browser extensions jigsaw icon and you will see Download Sentinel does not need access at all). 

_________________________ Using the extension

1. Click on the Download Sentinal icon and the banner shows the current status of the extension.
<img width="838" height="275" alt="image" src="https://github.com/user-attachments/assets/799ce443-99f7-4c92-88d4-9b4bbcd12c17" />


_________________________ What Download Sentinal does to protect you

DOWNLOAD SENTINEL

IMPORTANT NOTICE: DOWNLOAD SENTINEL DOES NOT BLOCK THE DOWNLOAD, IN STEAD IT PERFORMS ON-DOWNLOAD AND ON-FILE WRITE CHECKS TO WARN YOU FOR SNEAKY TACTICS WHICH WOULD NOT BE SIGNALED WHEN THE INITIAL DOWNLOAD WAS BLOCKED. AFTER THE DOWNLOAD FINISHES THE RESULTS ARE PRESENTED IN A WARNING POPUP. YOU CAN SUPPRESS THIS WARNING FOR ¨PROBABLY SAFE DOWNLOAD¨ IN THE OPTIONS.

Every time you download a file, Download Sentinel quietly runs a set of quick checks. No single check is proof of danger on its own; instead, each one adds or removes a few "trust points," and the final total decides whether the file looks Safe, Questionable, Suspicious, or Malicious.

1. HAS ANYONE ELSE ALREADY SPOTTED THIS FILE OR WEBSITE AS SUSPICIOUS?
We check at Virus Total if security companies have already flagged this download as dangerous — and for how long it’s been known safe or unsafe. We also check it against lists of known scam websites, like a phone number flagged as a scam caller.

2. CAN YOU TRUST THE WEBSITE AND DOWNLOAD LINK?
Some website endings (like odd “.xyz”-style ones) are used by scammers far more than real businesses. Brand-new websites are treated more cautiously than ones that have been around for years — scam sites often appear and vanish fast. We also catch fake lookalikes, like “m1crosoft” or “arnazon.com” instead of “amazon.com”.

3. IS THE (DOWNLOAD) FILE HIDING SOMETHING?
If a site says it’s sending a photo but actually sends a program, that’s a red flag. We catch sneaky tricks like “invoice.pdf.exe” (a program disguised as a document), file names secretly reversed so “evil.exe” looks like “safe.jpg”, and extra padding used to hide a dangerous ending from view. We also flag it if the file that arrives is riskier than what was promised, if it’s a bare script (something a home user rarely needs), or if it’s unusually large (too big to be fully scanned).

4. IS THE DOWNLOAD CONNECTION ITSELF RISKY?
We flag downloads sent without the padlock (HTTPS), links using a bare set of numbers instead of a real website name, links that quietly redirect somewhere else, and files served from free “throwaway” hosting often used to spread malware.


WHAT DOES THE WARNING PAGE SHOW?
The warning page shows a risk score based on what VirusTotal knows about the download address. The file itself is never sent to VirusTotal, which is better for your privacy and gives a faster result. After checking the results, you can choose to proceed, or to look up the download at VirusTotal (when it is known there), or at Hybrid Analysis for a free scan with Metadefender and Crowdstrike (when it is not known at VirusTotal yet).


OPTIONS PANEL
A false positive reduction level can be set to reduce unnecessary warnings for well-known safe software. Up to 12 trusted websites can be whitelisted so downloads from those sites are never checked. You can also set a minimum confidence level to skip the warning automatically when a download is probably safe (default is +80%). The background color and the title of the warning page can be changed to your personal preference.

https://chromewebstore.google.com/detail/download-sentinel/ofjlbohlnaihneapmmnhkbllbekdofce?pli=1

<img width="1845" height="668" alt="image" src="https://github.com/user-attachments/assets/8b346b95-c6c3-4436-bacc-c1403989132d" />





_________________________ What you need to set in the OPTIONS 

1. Signup to Virus Total to get a free API key and enter the key (required)
2. Click on the options button to enter your free Virus Total API key (https://www.virustotal.com/gui/join-us)
3. Optionally change the look and behavior of the warning page

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
- www.rdap.org        - because it check for the domain age (less than 30 days old is suspicious) 

_________________________  PRIVACY

It does not monitor nor save or transmit any of the URL's your are visiting. Only the download URL is handled over to Virus Total when it is an executable or compressed file download and NOT on the whitelist. Normal downloads (PDF's word documents, spreadsheets, powerpoints, movies, pictures, etc) are skipped. 

Privacy policy: https://github.com/Kees1958/DownloadSentinel/blob/main/privacy.md)


_________________________ Issues or suggestions

Please post issues or suggestions on https://github.com/Kees1958/DownloadSentinel/issues.



_________________________ License

This project is licensed under the GNU GPL v3.0 - see LICENSE file for details.
