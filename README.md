When an executable or compressed file is downloaded which does not come from a (user determined) whitelist or the build-in whitelist,
It shows a warning page and checks the download URL reputation on Virus Total and updates the warning page.
The user can decide to cancel & go back or ignore & proceed

The warning page shows a risk score which is determined on the information available on Virus Total of the download URL

<img width="828" height="812" alt="image" src="https://github.com/user-attachments/assets/ac68f079-4691-45ff-bd25-3030747251ba" />



_________________________ What you need to set in the OPTIONS 

1. Signup to Virus Total to get a free API key and enter the key (required)
2. Change the background color of the warning screen, which defaults to Google Safe Browsing (optional)
3. Enter up to 12 domains which are white listed to skip the download check of executables and archives for these websites (optional)

<img width="704" height="738" alt="image" src="https://github.com/user-attachments/assets/ddf86e2d-d5d7-4141-833b-efc7f4a9f441" />




_________________________  PERMISSIONS 

1. Download - because it has to intercept downloads
2. Options UI for pages/options/OptionsPage.html - because the extension has an options page 
3. Storage  - because it saves your Virus Total API key and domain whitelist you enter on the options page
4. Host permission for wwww.virustotal.com - because it checks the reputation of the download URL at VT

_________________________  PRIVACY

Only the download URL is handled over to Virus Total when it is an executable or compressed file download and NOT on the whitelist.
Normal downloads (PDF's word documents, spreadsheets, powerpoints, movies, pictures, etc) are skipped. 
It does not monitor nor save or transmit any of the URL's your are visiting. 
_________________________ Further development

I am not adding multi language support and not planning to make a Firefox version, but I will have a look at issues posted
https://github.com/Kees1958/DownloadSentinel/issues

_________________________ Why use it?

For people only using the default Safe Browsing protection in Chromium based browsers for privacy reasons, this extension fills in some gaps: go to https://testsafebrowsing.appspot.com/ 

<img width="1092" height="485" alt="image" src="https://github.com/user-attachments/assets/11e48f6d-3a34-42a7-b84b-efd1804bd8c0" />



