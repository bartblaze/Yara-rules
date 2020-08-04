rule Monero_Compromise
{
meta:
	description = "Identifies compromised Monero binaries."
	author = "@bartblaze"
	date = "2019-11"
	reference = "https://bartblaze.blogspot.com/2019/11/monero-project-compromised.html"
	tlp = "White"

strings:
	$ = "ZN10cryptonote13simple_wallet9send_seedERKN4epee15wipeable_stringE" ascii wide
	$ = "ZN10cryptonote13simple_wallet10send_to_ccENSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEES6_i" ascii wide
	$ = "node.xmrsupport.co" ascii wide
	$ = "node.hashmonero.com" ascii wide

condition:
	any of them
}
