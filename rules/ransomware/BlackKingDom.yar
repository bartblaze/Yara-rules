rule BlackKingDom
{
meta:
	description = "Identifies (decompiled) Black KingDom ransomware."
	author = "@bartblaze"
	date = "2021-03"
	hash = "866b1f5c5edd9f01c5ba84d02e94ae7c1f9b2196af380eed1917e8fc21acbbdc"
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
