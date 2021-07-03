import "pe"
rule REvil_Cert
{
meta:
	description = "Identifies the digital certificate PB03 TRANSPORT LTD, used by REvil in the Kaseya supply chain attack."
	author = "@bartblaze"
	date = "2021-07"
	reference = "https://community.sophos.com/b/security-blog/posts/active-ransomware-attack-on-kaseya-customers"
	tlp = "White"
	
condition:
	uint16(0) == 0x5a4d and
		for any i in (0 .. pe.number_of_signatures) : (
		pe.signatures[i].serial == "11:9a:ce:ad:66:8b:ad:57:a4:8b:4f:42:f2:94:f8:f0"
	)
}
