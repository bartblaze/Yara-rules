import "pe"
rule PowerTool
{
meta:
	description = "Identifies PowerTool, sometimes used by attackers to disable security software."
	author = "@bartblaze"
	date = "2021-07"
	reference = "https://www.softpedia.com/get/Antivirus/Removal-Tools/ithurricane-PowerTool.shtml"
	tlp = "White"
	
strings:
	$ = "C:\\dev\\pt64_en\\Release\\PowerTool.pdb" ascii wide
	$ = "Detection may be stuck, First confirm whether the device hijack in [Disk trace]" ascii wide
	$ = "SuspiciousDevice Error reading MBR(Kernel Mode) !" ascii wide
	$ = "Modify kill process Bug." ascii wide
	$ = "Chage language nedd to restart PowerTool" ascii wide
	$ = ".?AVCPowerToolApp@@" ascii wide
	$ = ".?AVCPowerToolDlg@@" ascii wide

condition:
	any of them
}
 