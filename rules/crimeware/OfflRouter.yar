rule OfflRouter
{
meta:
	description = "Identifies OfflRouter, malware which spreads to Office documents and removable drives."
	author = "@bartblaze"
	date = "2022-01-01"
	reference = "https://www.csirt.gov.sk/wp-content/uploads/2021/08/analysis_offlrouter.pdf"
	tlp = "White"

strings:
	/*
	Dim num As Long = 0L
	Dim num2 As Long = CLng((Bytes.Length - 1))
	For num3 As Long = num To num2
	Bytes(CInt(num3)) = (Bytes(CInt(num3)) Xor CByte(((num3 + CLng(Bytes.Length) + 1L) Mod &H100L)))
	*/
	$ = { 16 6A 02 50 8E B7 17 59 6A 0B 0A 2B 22 02 50 06 69 02 50 06 69 91 06 02 50 8E B7 6A 58 17 6A 58 20 00 01 00 00 6A 5D D2 61 9C 06 17 6A 58 0A 06 07 }

condition:
	all of them
}
