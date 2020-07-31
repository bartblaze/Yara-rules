rule RagnarLocker
{
meta:
	description = "Identifies RagnarLocker ransomware unpacked or in memory."
	author = "@bartblaze"
	date = "2020-07"
	tlp = "White"
	
strings:
	$ = "RAGNRPW" ascii wide
	$ = "---END KEY R_R---" ascii wide
	$ = "---BEGIN KEY R_R---" ascii wide

condition:
	any of them
}