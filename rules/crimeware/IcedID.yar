rule IcedID
{
meta:
	description = "Identifies IcedID (stage 1 and 2, loaders)."
	author = "@bartblaze"
	date = "2021-01"
	tlp = "White"
	
strings:
	$s1 = "{%0.8X-%0.4X-%0.4X-%0.4X-%0.4X%0.8X}" ascii wide
	$s2 = "%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.8X" ascii wide
	$s3 = "/image/?id=%0.2X%0.8X%0.8X%s" ascii wide
	
	$x1 = "; _gat=" ascii wide
	$x2 = "; _ga=" ascii wide
	$x3 = "; _u=" ascii wide
	$x4 = "; __io=" ascii wide
	$x5 = "; _gid=" ascii wide
	$x6 = "Cookie: __gads=" ascii wide

condition:
	2 of ($s*) or 3 of ($x*)
}
