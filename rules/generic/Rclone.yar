import "pe"
import "hash"
rule Rclone
{
meta:
	description = "Identifies Rclone, sometimes used by attackers to exfiltrate data."
	author = "@bartblaze"
	date = "2021-07"
	reference = "https://rclone.org/"
	tlp = "White"
	
strings:
	$ = "github.com/rclone/" ascii wide
	$ = "The Rclone Authors" ascii wide
	$ = "It copies the drive file with ID given to the path" ascii wide
	$ = "rc vfs/forget file=hello file2=goodbye dir=home/junk" ascii wide
	$ = "rc to flush the whole directory cache" ascii wide

condition:
	any of them or 
	for any i in (0..pe.number_of_resources - 1):
	(pe.resources[i].type == pe.RESOURCE_TYPE_ICON and
	hash.md5(pe.resources[i].offset, pe.resources[i].length) ==
	"fc675e36c61c8b9d0b956bd05695cdda")
}