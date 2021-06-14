import "dotnet"
rule RedLine_Campaign_June2021
{
meta:
	description = "Identifies RedLine stealer's June 2021 campaign."
	author = "@bartblaze"
	date = "2021-06"
	tlp = "White"

condition:
	dotnet.guids[0] == "a862cb90-79c7-41a9-847b-4ce4276feaeb" or
	dotnet.guids[0] == "a955bdf8-f5ac-4383-8f5d-a4111125a40e" or
	dotnet.guids[0] == "018ca516-2128-434a-b7c6-8f9a75dfc06e" or
	dotnet.guids[0] == "829c9056-6c93-42c2-a9c8-19822ccac0a4" or
	dotnet.guids[0] == "e1a702b0-dee1-463a-86d3-e6a9aa86348e" or
	dotnet.guids[0] == "6152d28b-1775-47e6-902f-8bdc9e2cb7ca" or
	dotnet.guids[0] == "111ab36c-09ad-4a3e-92b3-a01076ce68e0" or
	dotnet.guids[0] == "ea7dfb6d-f951-48e6-9e25-41c31080fd42"
}
