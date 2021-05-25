rule Avaddon
{
meta:
	description = "Identifies Avaddon ransomware."
	author = "@bartblaze"
	date = "2021-05"
	tlp = "White"

strings:
	$s1 = "\"ext\":" ascii wide
	$s2 = "\"rcid\":" ascii wide
	$s3 = "\"hdd\":" ascii wide
	$s4 = "\"name\":" ascii wide
	$s5 = "\"size\":" ascii wide
	$s6 = "\"type\":" ascii wide
	$s7 = "\"lang\":" ascii wide
	$s8 = "\"ip\":" ascii wide

	$code = { 83 7f 14 10 8b c7 c7 4? ?? 00 00 00 00 72 ?? 8b 07 6a 00 6a 00 
	8d ?? f8 51 6a 00 6a 01 6a 00 50 ff 15 ?? ?? ?? ?? 85 c0 74 ?? 56 
        8b 7? ?? ff 15 ?? ?? ?? ?? 56 6a 00 50 ff 15 ?? ?? ?? ?? 8b f0 85 
        f6 74 ?? 83 7f 14 10 72 ?? 8b 3f }

condition:
	4 of ($s*) or $code
}
