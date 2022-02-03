rule WhiteBlack
{
meta:
	description = "Identifies WhiteBlack ransomware."
	author = "@bartblaze"
	date = "2022-01-01"
	reference = "https://twitter.com/siri_urz/status/1377877204776976384"
	tlp = "White"

strings:
	//_Str2 = strcat(_Str2,".encrpt3d"); Encrypt block
	$ = { 55 57 56 53 4? 83 ec 28 31 db bd 00 01 00 00 89 cf 31 c9 ff 15 ?? ?? ?? ?? 89 c1 e8 ?? ?? ?? ?? 4? 63 cf e8 ?? ?? ?? ?? 4? 89 c6 39 df 7e ?? e8 ?? ?? ?? ?? 99 f7 fd 88 14 1e 4? ff c3 eb ?? 4? 89 f0 4? 83 c4 28 5b 5e 5f 5d c3 4? 55 4? 54 55 57 56 53 4? 83 ec 28 4? 8d 15 ?? ?? ?? ?? 31 f6 4? 8d 2d ?? ?? ?? ?? 4? 89 cd e8 ?? ?? ?? ?? b9 00 00 00 02 4? 89 c3 e8 ?? ?? ?? ?? 4? 89 c7 4? 89 d9 4? b8 00 00 00 02 ba 01 00 00 00 4? 89 f9 e8 ?? ?? ?? ?? 85 c0 4? 89 c4 74 ?? 81 fe ff ff ff 3f 7f ?? 4? 89 e0 4? 89 fa 4? 89 e? e8 ?? ?? ?? ?? 4? 31 c0 89 f2 4? 89 d9 e8 ?? ?? ?? ?? 4? 01 e6 4? 63 c4 4? 89 f9 4? 89 d9 ba 01 00 00 00 e8 ?? ?? ?? ?? 4? 31 c0 89 f2 4? 89 d9 e8 ?? ?? ?? ?? eb ?? 4? 89 f9 4? 89 ef e8 ?? ?? ?? ?? 4? 89 d9 e8 ?? ?? ?? ?? 31 c0 4? 83 c9 ff f2 ae 4? 89 ce 4? f7 d6 4? 89 f1 4? 83 c1 09 e8 ?? ?? ?? ?? 4? 89 ea 4? 89 c1 e8 ?? ?? ?? ?? 4? 8d 15 ?? ?? ?? ?? 4? 89 c1 e8 ?? ?? ?? ?? 4? 89 e9 4? 89 c2 4? 83 c4 28 }

condition:
	any of them
}
