import "pe"
rule Gmer
{
meta:
	description = "Identifies Gmer, sometimes used by attackers to disable security software."
	author = "@bartblaze"
	date = "2021-07-01"
	reference = "http://www.gmer.net/"
	tlp = "White"
	
strings:
	$ = "GMER %s - %s" ascii wide
	$ = "IDI_GMER" ascii wide fullword
	$ = "E:\\projects\\cpp\\gmer\\Release\\gmer.pdb" ascii wide
	
condition:
	any of them
}
 