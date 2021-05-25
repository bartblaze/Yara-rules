rule Darkside
{
meta:
	description = "Identifies Darkside ransomware."
	author = "@bartblaze"
	date = "2021-05"
	tlp = "White"

strings:
	$ = "darkside_readme.txt" ascii wide
	$ = "[ Welcome to DarkSide ]" ascii wide
	$ = { 66 c7 04 47 2a 00 c7 44 47 02 72 00 65 00 c7 44 47 06 63 00 79 00 c7 44 47 0a 63 00 6c 00 c7 44 47 0e 65 00 2a 00 66 c7 44 47 12 00 00 }
	$ = { c7 00 2a 00 72 00 c7 40 04 65 00 63 00 c7 40 08 79 00 63 00 c7 40 0c 6c 00 65 00 c7 40 10 2a 00 00 00 }

condition:
	any of them
}
