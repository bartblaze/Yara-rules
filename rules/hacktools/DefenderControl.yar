import "pe"
import "hash"
rule DefenderControl
{
meta:
	description = "Identifies Defender Control, used by attackers to disable Windows Defender."
	author = "@bartblaze"
	date = "2021-04"
	reference = "https://www.sordum.org/9480/defender-control-v1-8/"
	tlp = "White"

strings:
	$ = "www.sordum.org" ascii wide
	$ = "dControl.exe" ascii wide

condition:
	all of them or (
	for any i in (0..pe.number_of_resources - 1):
	(pe.resources[i].type == pe.RESOURCE_TYPE_ICON and
	hash.md5(pe.resources[i].offset, pe.resources[i].length) ==
	"ff620e5c0a0bdcc11c3b416936bc661d")
	)
}
