import "pe"
rule Gmer_Driver
{
meta:
	description = "Identifies Gmer's driver, sometimes used by attackers to disable security software."
	author = "@bartblaze"
	date = "2021-07"
	reference = "http://www.gmer.net/"
	tlp = "White"

strings:
	$ = "e:\\projects\\cpp\\gmer\\driver64\\objfre_wlh_amd64\\amd64\\gmer64.pdb" ascii wide
	$ = "GMER Driver http://www.gmer.net" ascii wide

condition:
	any of them or
	pe.version_info["OriginalFilename"] contains "gmer64.sys" or 
	pe.version_info["InternalName"] contains "gmer64.sys" 
}