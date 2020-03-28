rule Satan_Mutexes
{
meta:
	description = "Identifies Satan ransomware (and its variants) by mutex."
	author = "@bartblaze"
	date = "2020-01"
	reference = "https://bartblaze.blogspot.com/2020/01/satan-ransomware-rebrands-as-5ss5c.html"
	tlp = "White"
strings:
	$ = "SATANAPP" ascii wide
	$ = "SATAN_SCAN_APP" ascii wide
	$ = "STA__APP" ascii wide
	$ = "DBGERAPP" ascii wide
	$ = "DBG_CPP" ascii wide
	$ = "run_STT" ascii wide
	$ = "SSS_Scan" ascii wide
	$ = "SSSS_Scan" ascii wide
	$ = "5ss5c_CRYPT" ascii wide
condition:
	any of them
}
