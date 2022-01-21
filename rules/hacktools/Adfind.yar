rule Adfind
{
meta:
	description = "Identifies Adfind, a Command line Active Directory query tool."
	author = "@bartblaze"
	date = "2020-08-01"
	reference = "http://www.joeware.net/freetools/tools/adfind/"
	tlp = "White"

strings:
	$ = "E:\\DEV\\cpp\\vs\\AdFind\\AdFind\\AdFind.cpp" ascii wide
	$ = "adfind.cf" ascii wide
	$ = "adfind -" ascii wide
	$ = "adfind /" ascii wide
	$ = "you have encountered a STAT binary blob that" ascii wide

condition:
	any of them
}