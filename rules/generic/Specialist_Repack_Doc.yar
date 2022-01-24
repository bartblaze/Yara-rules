rule Specialist_Repack_Doc
{
meta:
	description = "Identifies Office documents created by a cracked Office version, SPecialiST RePack."
	author = "@bartblaze"
	date = "2022-01-01"
	reference = "https://twitter.com/malwrhunterteam/status/1483132689586831365"
	tlp = "White"

strings:
	$ = "SPecialiST RePack" ascii wide
	$ = {53 50 65 63 69 61 6C 69 53 54 20 52 65 50 61 63 6B} //same as above

condition:
	any of them
}
