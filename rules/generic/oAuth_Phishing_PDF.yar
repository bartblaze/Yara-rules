rule oAuth_Phishing_PDF
{
meta:
	description = "Identifies potential phishing PDFs that target oAuth."
	author = "@bartblaze"
	date = "2022-01"
	reference = "https://twitter.com/ffforward/status/1484127442679836676"
	tlp = "White"

strings:
	$pdf = {25504446} //%PDF
	$s1 = "/URI (https://login.microsoftonline.com/common/oauth2/" ascii wide nocase
	$s2 = "/URI (https://login.microsoftonline.com/consumers/oauth2" ascii wide nocase
	$s3 = "/URI (https://accounts.google.com/o/oauth2" ascii wide nocase

condition:
	$pdf at 0 and any of ($s*)
}
