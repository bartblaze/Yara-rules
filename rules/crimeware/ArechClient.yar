rule ArechClient
{
meta:
	description = "Identifies ArechClient, infostealer."
	author = "@bartblaze"
	date = "2021-07-01"
	tlp = "White"
	
strings:
	$ = "is_secure" ascii wide
	$ = "encrypted_value" ascii wide
	$ = "host_keyexpires_utc" ascii wide

condition:
	all of them
}