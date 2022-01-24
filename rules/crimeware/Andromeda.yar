rule Andromeda
{
    meta:
        id = "66EiRJfwdRpNnHru6KDjKX"
        fingerprint = "45a5315e4ffe5156ce4a7dc8e2d6e27d6152cd1d5ce327bfa576bf0c4a4767d8"
        version = "1.0"
        creation_date = "2021-03-01"
        first_imported = "2022-01-24"
        last_modified = "2022-01-24"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Andromeda aka Gamarue botnet."
        category = "MALWARE"

    strings:
		//IndexerVolumeGuid
        $ = { 8d ?? dc fd ff ff 50 8d ?? d8 fd ff ff 50 e8 ?? ?? ?? ?? 8a 00 53 68 ?? ?? ?? ?? 56
    ff b? ?? ?? ?? ?? a2 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 18 53 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 53
    53 ff 15 ?? ?? ?? ?? ff b? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 83 f8
    ff 74 ?? 6a 01 50 ff 15 ?? ?? ?? ?? }
        $ = { 83 c4 10 ff b? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff b? ?? ?? ?? ?? ff b?
    ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? }
        $ = { 36 8a 94 28 00 ff ff ff 02 da 36 8a b4 2b 00 ff ff ff 36 88 b4 28 00 ff ff ff 36 88 94 2b 00 ff ff ff }

		/*
		MOV        DL ,byte ptr SS :[EAX  + EBP *0x1  + 0xffffff00 ]
		MOV        DH ,byte ptr SS :[EBX  + EBP *0x1  + 0xffffff00 ]
		MOV        byte ptr SS :[EAX  + EBP *0x1  + 0xffffff00 ],DH
		MOV        byte ptr SS :[EBX  + EBP *0x1  + 0xffffff00 ],DL
		*/

    condition:
        any of them
}
