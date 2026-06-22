As of version 1.1 this extension warns for potential harmful downloads (archive file format or executable mime type or file format) and check the reputation of the download URL at Virus Total when the user has entered his/her FREE Virus Total API key. The extensions shows a risk assessments and the user can either choose to cancel & go back or ignore & proceed option. When the download is unknown at VT, it offers an link to Virus Total to manually check the download.

When download URL is unknown at Virus Total, it checks whether the download domain is blacklisted at Quad9 and determines the age at RDAP. It also checks (using an internal list) whether the domain is a free hosting or code sharing domain often used to spread malware and checks whether the Top Level Domain is on much abused TLD list. 

It also checks whether the download-URL is sketchy (e.g. includes punycode, mentions well known brands or uses numbers for characters e.g 1 for l and 0 for 0) uses a different mime type than file format and exceeds VirusTotal size maximum (many Antivirus don´t check files which are to large). 

The warning page shows a risk score which is determined based on the information available on Virus Total of the download URL. Note that the content of 
the downloaded file is never send to Virus Total. Checking only the URL has a privacy and response time advantage. 

<img width="832" height="815" alt="image" src="https://github.com/user-attachments/assets/63f11d7a-cdfb-48cf-bdb4-ecd9bcae73d1" />

.

_________________________ What you need to set in the OPTIONS 

1. Signup to Virus Total to get a free API key and enter the key (required)
2. Change the background color of the warning screen, which defaults to Google Safe Browsing (optional)
3. Enter up to 12 domains which are white listed to skip the download check of executables and archives for these websites (optional)

<img width="704" height="738" alt="image" src="https://github.com/user-attachments/assets/ddf86e2d-d5d7-4141-833b-efc7f4a9f441" />

_________________________ Using the extension

1. It runs in the background doing warning you for potentially harmful downloads.
2. Click on the Download Sentinal icon and the banner shows the current status of the extension.
3. Click on the options button to enter your free Virus Total API key (https://www.virustotal.com/gui/join-us)
<img width="838" height="275" alt="image" src="https://github.com/user-attachments/assets/799ce443-99f7-4c92-88d4-9b4bbcd12c17" />



_________________________  PERMISSIONS 

1. Download - because it has to intercept downloads
2. Options UI for pages/options/OptionsPage.html - because the extension has an options page 
3. Storage  - because it saves your Virus Total API key and domain whitelist you enter on the options page
4. Host permission for   
- www.virustotal.com - because it checks the reputation of the download URL at VTHost permission 
- www.quad9.com      - because it checks whether the domain of the download URL is on Quad9 blacklist
- www.rdap.org        - because it check for the domain age (less 30 days is suspicious) 

_________________________  PRIVACY

It does not monitor nor save or transmit any of the URL's your are visiting. Only the download URL is handled over to Virus Total when it is an executable or compressed file download and NOT on the whitelist. Normal downloads (PDF's word documents, spreadsheets, powerpoints, movies, pictures, etc) are skipped. 

Privacy policy: https://github.com/Kees1958/DownloadSentinel/blob/main/privacy.md)

_________________________ Further development

I am not planning to add multi language or firefox support. 

_________________________ Issues or suggestions

Please post issues or suggestions on https://github.com/Kees1958/DownloadSentinel/issues.



_________________________ Why use it?

For people only using the default Safe Browsing protection in Chromium based browsers for privacy reasons, this extension fills in some gaps: go to https://testsafebrowsing.appspot.com/ Other possible use cases are people who use a browser which does not has Google Safe Browsing advanced mode for privacy reasons (e.g. Brave) or does not has any Google services (e.g. Ungoogled Chromium).

<img width="1092" height="485" alt="image" src="https://github.com/user-attachments/assets/11e48f6d-3a34-42a7-b84b-efd1804bd8c0" />



