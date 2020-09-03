rule Avaddon
{
meta:
	description = "Identifies Avaddon ransomware."
	author = "@bartblaze"
	date = "2020-09"
	tlp = "White"

strings:
	$ = "\"rcid\":\"" ascii wide fullword
	$ = "\"hdd\":\"" ascii wide fullword
	$ = "\"ext\":\"" ascii wide fullword
	$ = "\"ip\":\"" ascii wide fullword

condition:
	3 of them
}