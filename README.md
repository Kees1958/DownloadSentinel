This is the release candidate of en extension to help protect against risky downloads.

The extension uses an internal list of Windows/Mac/Linux executables, compressed files and domains often used to spread malware.

When an executable or compressed file is downloaded which does not come from a (user determined( whitelist, 

It shows a warning page and checks the download URL reputation on Virus Total and uodates the warning page.
The user can decide to cancel & go back or ignore & proceed

The same check is performed for ANY downloaded file coming from a domain which is often used to spread malware.

_________________________  PERMISSIONS 

1. Download - because it has to intercept downloads
2. Storage  - because it saves your personal Virus Total API key and a small (max 10) domain whitelist
3. Host permission for wwww.virustotal.com - because it checks the reputation of the download URL

_________________________  PRIVACY

Only the download URL is handled over to Virus Total when it is a risky download and NOT on the whitelist.
Normal downloads (PDF's word documents, spreadsheets, powerpoints, movies, pictures, etc) are skipped. 
It does not monitor nor save or transmit any of the URL's your are visiting. 

_________________________ What you need to set in the OPTIONS 
1. Signup to Virus Total to get a free license key
2. Enter up to 12 domains which are white listed.
3. You can change the back ground color of the warning page

_________________________ Further development
I am not adding multi language support, it is an extension for personal use which I making available to others.
I am using Brave (Chromium) so not planning to make a Firefox version.



<img width="710" height="764" alt="image" src="https://github.com/user-attachments/assets/880c41e0-da3c-4f80-961e-8f79de3902ed" />


