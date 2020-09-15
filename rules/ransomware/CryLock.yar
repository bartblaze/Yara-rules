rule CryLock
{
meta:
	description = "Identifies CryLock aka Cryakl ransomware."
	author = "@bartblaze"
	date = "2020-09"
	tlp = "White"
	
strings:
	$ = "///END ENCRYPT ONLY EXTENATIONS" ascii wide
	$ = "///END UNENCRYPT EXTENATIONS" ascii wide
	$ = "///END COMMANDS LIST" ascii wide
	$ = "///END PROCESSES KILL LIST" ascii wide
	$ = "///END SERVICES STOP LIST" ascii wide
	$ = "///END PROCESSES WHITE LIST" ascii wide
	$ = "///END UNENCRYPT FILES LIST" ascii wide
	$ = "///END UNENCRYPT FOLDERS LIST" ascii wide
	$ = "{ENCRYPTENDED}" ascii wide
	$ = "{ENCRYPTSTART}" ascii wide

condition:
	2 of them
}