rule PurpleFox_a
{
meta:
	description = "Identifies PurpleFox aka DirtyMoe botnet."
	author = "@bartblaze"
	date = "2021-11"
	tlp = "White"

strings:
	/*
    0042b88a 4c  8d  05  LEA R8 ,[s_???????.tmp_0042b9b0 ] = "???????.tmp"
	*/
	$movetmp = { 4? 8d 4d 38 4? 8b 95 88 01 00 00 4? 8d 05 1f 01 00 00 e8 9a c8 fd ff 4? 8b 4d 38 e8 51 cc fd ff 4? 89 c1 4? 8d 55 48 e8 55 07 fe ff 4? 89 c3 4? 83 fb ff 74 74 8b 45 48 83 e0 10 83 f8 10 74 50 4? 8d 4d 30 4? 8d 55 74 4? c7 c0 04 01 00 00 4? 33 c9 e8 9a c6 fd ff 4? 8d 4d 40 4? 8b 95 88 01 00 00 4? 8b 45 30 e8 46 c8 fd ff 4? 8b 4d 40 e8 fd cb fd ff 4? 89 c1 4? 33 d2 e8 c2 09 fe ff 4? 8b 4d 40 e8 e9 cb fd ff 4? 89 c1 e8 a1 06 fe ff 4? 89 d9 4? 8d 55 48 e8 f5 06 fe ff 85 c0 75 95 4? 89 d9 e8 19 3d fe ff  }

condition:
	all of them
}

rule PurpleFox_b
{
meta:
	description = "Identifies PurpleFox aka DirtyMoe botnet."
	author = "@bartblaze"
	date = "2021-11"
	tlp = "White"

strings:
	//Default device name starts with \\dump_
	$ = /dump_[A-Z0-9]{8}/ ascii wide
	$ = "cscdll.dll" ascii wide
	$ = "sens.dll" ascii wide

condition:
	all of them
}


rule PurpleFox_c
{
meta:
	description = "Identifies PurpleFox aka DirtyMoe botnet."
	author = "@bartblaze"
	date = "2021-11"
	tlp = "White"

strings:
	$ = "UpProxyRandom" ascii wide
	$ = "SetServiceName" ascii wide
	$ = "DrvServiceName" ascii wide
	$ = "DriverOpenName" ascii wide
	$ = "DirLogFilePath" ascii wide
	$ = "RunPeShellPath" ascii wide
	$ = "DriverFileName" ascii wide

condition:
	all of them
}

rule PurpleFox_Dropper
{
meta:
	description = "Identifies PurpleFox aka DirtyMoe botnet, dropper CAB or MSI package."
	author = "@bartblaze"
	date = "2021-11"
	tlp = "White"

strings:
	$doc = {D0 CF 11 E0}
	$cab = {4D 53 43 46}
	
	$s1 = "sysupdate.log" ascii wide
	$s2 = "winupdate32.log" ascii wide
	$s3 = "winupdate64.log" ascii wide

condition:
	($doc at 0 and all of ($s*)) or
	($cab at 0 and all of ($s*))
}
