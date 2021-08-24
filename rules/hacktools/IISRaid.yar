rule IISRaid
{
meta:
	description = "Identifies IISRaid."
	author = "@bartblaze"
	date = "2021-08"
	reference = "https://github.com/0x09AL/IIS-Raid"
	tlp = "White"

strings:
	$pdb1 = "\\IIS-Raid-master\\" ascii wide
	$pdb2 = "\\IIS-Backdoor.pdb" ascii wide

	$s1 = "C:\\Windows\\System32\\credwiz.exe" ascii wide
	$s2 = "C:\\Windows\\Temp\\creds.db" ascii wide
	$s3 = "CHttpModule::" ascii wide
	$s4 = "%02d/%02d/%04d %02d:%02d:%02d | %s" ascii wide

condition:
	any of ($pdb*) or 3 of ($s*)
}
