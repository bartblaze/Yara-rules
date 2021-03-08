rule Andromeda
{
meta:
	description = "Identifies Andromeda aka Gamarue botnet, USB worm module."
	author = "@bartblaze"
	date = "2021-03"
	tlp = "White"

strings:
	$code = { 8d 85 dc fd ff ff 50 8d 85 d8 fd ff ff 50 e8 1a fe ff ff 8a 00 53 68 d0 72 01 10 56 ff b5 
        f0 fd ff ff a2 28 f1 01 10 e8 eb 0e 00 00 83 c4 18 53 ff 15 68 51 01 10 68 d4 72 01 10 53 53 ff 
        15 60 51 01 10 ff b5 f0 fd ff ff ff 15 64 51 01 10 ff 15 6c 50 01 10 a3 f4 f6 01 10 83 f8 ff 74 
        09 6a 01 50 ff 15 20 50 01 10 }

condition:
	$code
}
