import "pe"
rule Cotx_RAT
{
meta:
	description = "Identifies Cotx RAT."
	author = "@bartblaze"
	date = "2019-07"
	reference = "https://www.proofpoint.com/us/threat-insight/post/chinese-apt-operation-lagtime-it-targets-government-information-technology"
	tlp = "White"
	
strings:
	$ = "%4d-%02d-%02d %02d:%02d:%02d" ascii wide
	$ = "%hs|%hs|%hs|%hs|%hs|%hs|%hs" ascii wide
	$ = "%hs|%s|%hs|%s|%s|%s|%s|%s|%s|%s|%hs" ascii wide
	$ = "%s;%s;%s;%.2f GB;%.2f GB|" ascii wide
	$ = "Cmd shell is not running,or your cmd is error!" ascii wide
	$ = "Domain:    [%s]" ascii wide
	$ = "Error:Cmd file not exists!" ascii wide
	$ = "Error:Create read pipe error!" ascii wide
	$ = "Error:No user is logoned!" ascii wide
	$ = "Error:You have in a shell,please exit first!" ascii wide
	$ = "Error:You have in a shell,please exit it first!" ascii wide
	$ = "Error:cmd.exe not exist!" ascii wide
	$ = "LogonUser: [%s]" ascii wide
	$ = "WriteFile session error!" ascii wide
	$ = "You have no permission to write on" ascii wide
	$ = "cannot delete directory:" ascii wide
	$ = "cannot delete file:" ascii wide
	$ = "cannot upload file to %s" ascii wide
	$ = "copy failed:" ascii wide
	$ = "exec failed:" ascii wide
	$ = "exec ok:" ascii wide
	$ = "explorer.exe" ascii wide
	$ = "file list error:open path [%s] error." ascii wide
	$ = "is already exist!" ascii wide
	$ = "is not exist!" ascii wide
	$ = "not exe:" ascii wide
	$ = "open file error:" ascii wide
	$ = "read file error:" ascii wide
	$ = "set config items error." ascii wide
	$ = "set config ok." ascii wide

condition:
	5 of them or (
	for any i in (0..pe.number_of_sections - 1): (
	pe.sections[i].name == ".cotx") )
}
