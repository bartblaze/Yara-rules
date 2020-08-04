rule CrunchyRoll
{
meta:
	description = "Identifies malware used in CrunchyRoll website hack."
	author = "@bartblaze"
	date = "2019-11"
	reference = "https://bartblaze.blogspot.com/2017/11/crunchyroll-hack-delivers-malware.html"
	tlp = "White"
	
strings:
	$ = "C:\\Users\\Ben\\Desktop\\taiga-develop\\bin\\Debug\\Taiga.pdb" ascii wide
	$ = "c:\\users\\ben\\source\\repos\\svchost\\Release\\svchost.pdb" ascii wide

condition:
	any of them
}
