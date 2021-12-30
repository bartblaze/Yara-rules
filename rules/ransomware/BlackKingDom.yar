rule BlackKingDom
{
meta:
	description = "Identifies (decompiled) Black KingDom ransomware."
	author = "@bartblaze"
	date = "2021-03-01"
	tlp = "White"

strings:
	$ = "BLACLIST" ascii wide
	$ = "Black KingDom" ascii wide
	$ = "FUCKING_WINDOW" ascii wide
	$ = "PleasStopMe" ascii wide
	$ = "THE AMOUNT DOUBLED" ascii wide
	$ = "WOWBICH" ascii wide
	$ = "clear_logs_plz" ascii wide
	$ = "decrypt_file.TxT" ascii wide
	$ = "disable_Mou_And_Key" ascii wide
	$ = "encrypt_file" ascii wide
	$ = "for_fortnet" ascii wide
	$ = "start_encrypt" ascii wide
	$ = "where_my_key" ascii wide
	
condition:
	3 of them
}
