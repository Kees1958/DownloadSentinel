When an executable or compressed file is downloaded which does not come from a (user determined) whitelist or the build-in whitelist,
It shows a warning page and checks the download URL reputation on Virus Total and updates the warning page with the results found for the download URL.
The user can decide to cancel & go back or ignore & proceed

The warning page shows a risk score which is determined based on the information available on Virus Total of the download URL. Note that the content of 
the downloaded file is never send to Virus Total. Checking only the URL has a privacy and response time advantage. 

<img width="835" height="829" alt="image" src="https://github.com/user-attachments/assets/023cbb02-e1f8-47ec-9912-a24a87c3c20f" />



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
4. Host permission for wwww.virustotal.com - because it checks the reputation of the download URL at VT

_________________________  PRIVACY

It does not monitor nor save or transmit any of the URL's your are visiting. 
Only the download URL is handled over to Virus Total when it is an executable or compressed file download and NOT on the whitelist.
Normal downloads (PDF's word documents, spreadsheets, powerpoints, movies, pictures, etc) are skipped. 

_________________________ Further development

First the extension has to be accepted by Google (first time always takes a bit longer). 
Next version will have a second (more permissive) risk scoring mechanism and a send to Virus Total option. 
I am not planning to add multi language or firefox support. 

_________________________ Issues or suggestions

Please post issues or suggestions on https://github.com/Kees1958/DownloadSentinel/issues.



_________________________ Why use it?

For people only using the default Safe Browsing protection in Chromium based browsers for privacy reasons, this extension fills in some gaps: go to https://testsafebrowsing.appspot.com/ Other possible use cases are people who use a browser which does not has Google Safe Browsing advanced mode for privacy reasons (e.g. Brave) or does not has any Google services (e.g. Ungoogled Chromium).

<img width="1092" height="485" alt="image" src="https://github.com/user-attachments/assets/11e48f6d-3a34-42a7-b84b-efd1804bd8c0" />



