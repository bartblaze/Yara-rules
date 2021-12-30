rule JSSLoader
{
meta:
	description = "Identifies FIN7's JSSLoader."
	author = "@bartblaze"
	date = "2021-06-01"
	tlp = "White"

strings:
	$s1 = "host" ascii wide fullword
	$s2 = "domain" ascii wide fullword
	$s3 = "user" ascii wide fullword
	$s4 = "processes" ascii wide fullword
	$s5 = "name" ascii wide fullword
	$s6 = "pid" ascii wide fullword
	$s7 = "desktop_file_list" ascii wide fullword
	$s8 = "file" ascii wide fullword
	$s9 = "size" ascii wide fullword
	$s10 = "adinfo" ascii wide fullword
	$s11 = "no_ad" ascii wide fullword
	$s12 = "adinformation" ascii wide fullword
	$s13 = "part_of_domain" ascii wide fullword
	$s14 = "pc_domain" ascii wide fullword
	$s15 = "pc_dns_host_name" ascii wide fullword
	$s16 = "pc_model" ascii wide fullword
	
	$x1 = "/?id=" ascii wide
	$x2 = "failed start exe" ascii wide
	$x3 = "Sending timer request failed, error code" ascii wide
	$x4 = "Internet connection failed, error code" ascii wide
	$x5 = "Sending initial request failed, error code" ascii wide

condition:
	14 of ($s*) or 3 of ($x*)
}
