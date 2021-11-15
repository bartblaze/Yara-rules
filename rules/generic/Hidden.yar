rule Hidden
{
meta:
	description = "Identifies Hidden Windows driver, used by malware such as PurpleFox."
	author = "@bartblaze"
	date = "2021-11"
	reference = "https://github.com/JKornev/hidden"
	tlp = "White"

strings:
	$ = "Hid_State" ascii wide
	$ = "Hid_StealthMode" ascii wide
	$ = "Hid_HideFsDirs" ascii wide
	$ = "Hid_HideFsFiles" ascii wide
	$ = "Hid_HideRegKeys" ascii wide
	$ = "Hid_HideRegValues" ascii wide
	$ = "Hid_IgnoredImages" ascii wide
	$ = "Hid_ProtectedImages" ascii wide
	$ = "Hid_HideImages" ascii wide

condition:
	5 of them
}
