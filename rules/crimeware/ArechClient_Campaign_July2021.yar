import "dotnet"
rule ArechClient_Campaign_July2021
{
meta:
	description = "Identifies ArechClient stealer's July 2021 campaign."
	author = "@bartblaze"
	date = "2021-07"
	reference = "https://twitter.com/bcrypt/status/1420471176137113601"
	tlp = "White"

condition:
	dotnet.guids[0] == "10867a7d-8f80-4d52-8c58-47f5626e7d52" or
	dotnet.guids[0] == "7596afea-18b9-41f9-91dd-bee131501b08"
}