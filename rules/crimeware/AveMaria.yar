rule AveMaria
{
meta:
	description = "Identifies AveMaria aka WarZone RAT."
	author = "@bartblaze"
	date = "2020-11-01"
	tlp = "White"

strings:
	$ = "AVE_MARIA" ascii wide
	$ = "Ave_Maria Stealer OpenSource" ascii wide
	$ = "Hey I'm Admin" ascii wide
	$ = "WM_DISP" ascii wide fullword
	$ = "WM_DSP" ascii wide fullword
	$ = "warzone160" ascii wide

condition:
	3 of them
}

