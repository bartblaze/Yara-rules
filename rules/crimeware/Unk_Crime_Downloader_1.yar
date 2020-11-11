import "pe"
rule Unk_Crime_Downloader_1
{
meta:
	description = "Unknown downloader DLL, likely used by Emotet and/or TrickBot."
	author = "@bartblaze"
	date = "2020-10"
	hash = "3d2ca7dc3d7c0aa120ed70632f9f0a15"
	tlp = "White"
	
strings:
	$ = "LDR.dll" ascii wide fullword
	$ = "URLDownloadToFileA" ascii wide
	
condition:
	all of them or 
	pe.imphash() == "4f8a708f1b809b780e4243486a40a465"
}