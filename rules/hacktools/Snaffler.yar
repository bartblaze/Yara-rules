rule Snaffler
{
meta:
	id = "5uXVBBZcZtY8YooVYoOEQn"
	fingerprint = "1f97443bd29a0abd0e64458cdc8c999c55266b0e0cd503991ef2c57f4194cf5c"
	version = "1.0"
	date = "2026-08-26"
	modified = "2026-08-26"
	status = "RELEASED"
	sharing = "TLP:CLEAR"
	source = "BARTBLAZE"
	author = "@ChrisJr404"
	description = "Identifies Snaffler, a tool used to find credentials and other sensitive data on network shares and file systems in Active Directory environments."
	category = "MALWARE"
	malware_type = "HACKTOOL"
	reference = "https://github.com/SnaffCon/Snaffler"
	tool = "SNAFFLER"

strings:
	$banner = "by l0ss and Sh3r4 - github.com/SnaffCon/Snaffler" ascii wide

	$s1 = "SnaffleRunner" ascii wide
	$s2 = "SnafflerMessageType" ascii wide
	$s3 = "ShareResultLogFromMessage" ascii wide
	$s4 = "FileResultLogFromMessage" ascii wide
	$s5 = "Been Snafflin' for " ascii wide
	$s6 = "Snafflin' took " ascii wide
	$s7 = "Snaffler out." ascii wide
	$s8 = "Starting to look for readable shares..." ascii wide
	$s9 = "Normalising output, please wait..." ascii wide

condition:
	uint16(0) == 0x5A4D and ($banner or 4 of ($s*))
}
