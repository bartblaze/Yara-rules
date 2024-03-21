rule PureCrypter
{
    meta:
        id = "1zLgWF57AJIATVZNMOyilu"
        fingerprint = "43687ec89c0f6dc52e93395ae5966e25bc1c2d2c7634936b6e9835773af19fa3"
        version = "1.0"
        date = "2024-03-20"
        modified = "2024-03-21"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies PureCrypter, .NET loader and obfuscator."
        category = "MALWARE"
        malware_type = "LOADER"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.purecrypter"

strings:
    $s1 = "{11111-22222-20001-00001}" ascii wide fullword
    $s2 = "{11111-22222-20001-00002}" ascii wide fullword
    $s3 = "{11111-22222-40001-00001}" ascii wide fullword
    $s4 = "{11111-22222-40001-00002}" ascii wide fullword
    
    //{.1.1.1.1.1.-.2.2.2.2.2.-.2.0.0.0.1.-.0.0.0.0.1.}
    $x1 = {7B 00 31 00 31 00 31 00 31 00 31 00 2D 00 32 00 32 00 32 00 32 00 32 00 2D 00 32 00 30 00 30 00 30 00 31 00 2D 00 30 00 30 00 30 00 30 00 31 00 7D}
	
    //{.1.1.1.1.1.-.2.2.2.2.2.-.2.0.0.0.1.-.0.0.0.0.2.}
    $x2 = {7B 00 31 00 31 00 31 00 31 00 31 00 2D 00 32 00 32 00 32 00 32 00 32 00 2D 00 32 00 30 00 30 00 30 00 31 00 2D 00 30 00 30 00 30 00 30 00 32 00 7D}
	
    //{.1.1.1.1.1.-.2.2.2.2.2.-.4.0.0.0.1.-.0.0.0.0.1.}
    $x3 = {7B 00 31 00 31 00 31 00 31 00 31 00 2D 00 32 00 32 00 32 00 32 00 32 00 2D 00 34 00 30 00 30 00 30 00 31 00 2D 00 30 00 30 00 30 00 30 00 31 00 7D}
	
    //{.1.1.1.1.1.-.2.2.2.2.2.-.4.0.0.0.1.-.0.0.0.0.2.}
    $x4 = {7B 00 31 00 31 00 31 00 31 00 31 00 2D 00 32 00 32 00 32 00 32 00 32 00 2D 00 34 00 30 00 30 00 30 00 31 00 2D 00 30 00 30 00 30 00 30 00 32 00 7D}

condition:
    2 of ($s*) or 2 of ($x*)
}
