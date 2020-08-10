rule NLBrute
{
meta:
	description = "Identifies NLBrute, an RDP brute-forcing tool."
	author = "@bartblaze"
	date = "2020-08"
	tlp = "White"

strings:
	$ = "SERVER:PORT@DOMAIN\\USER;PASSWORD" ascii wide

condition:
	any of them
}