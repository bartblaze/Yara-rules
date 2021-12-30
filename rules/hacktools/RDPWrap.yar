rule RDPWrap
{
meta:
	description = "Identifies RDP Wrapper, sometimes used by attackers to maintain persistence."
	author = "@bartblaze"
	date = "2020-05-01"
	reference = "https://github.com/stascorp/rdpwrap"
	tlp = "White"

strings:
	$ = "rdpwrap.dll" ascii wide
	$ = "rdpwrap.ini" ascii wide
	$ = "RDP Wrapper" ascii wide
	$ = "RDPWInst" ascii wide
	$ = "Stas'M Corp." ascii wide
	$ = "stascorp" ascii wide

condition:
	any of them
}