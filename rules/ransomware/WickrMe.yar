rule WickrMe
{
meta:
	description = "Identifies WickrMe (aka Hello) ransomware."
	author = "@bartblaze"
	date = "2021-04"
	reference = "https://www.trendmicro.com/en_ca/research/21/d/hello-ransomware-uses-updated-china-chopper-web-shell-sharepoint-vulnerability.html"
	tlp = "White"

strings:
	$ = "[+] Config Service..." ascii wide
	$ = "[+] Config Services Finished" ascii wide
	$ = "[+] Config Shadows Finished" ascii wide
	$ = "[+] Delete Backup Files..." ascii wide
	$ = "[+] Generate contact file {0} successfully" ascii wide
	$ = "[+] Generate contact file {0} failed! " ascii wide
	$ = "[+] Get Encrypt Files..." ascii wide
	$ = "[+] Starting..." ascii wide
	$ = "[-] No Admin Rights" ascii wide
	$ = "[-] Exit" ascii wide
  
condition:
	4 of them
}
