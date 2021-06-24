rule Unk_BR_Banker
{
meta:
	description = "Identifies an unknown Brazilian banking trojan."
	author = "@bartblaze"
	date = "2021-06"
	tlp = "White"

strings:
	$ = "<ALARME>" ascii wide
	$ = "<ALARME_G>" ascii wide
	$ = "<ALARME_R>" ascii wide
	$ = "<|LULUZDC|>" ascii wide
	$ = "<|LULUZLD|>" ascii wide
	$ = "<|LULUZLU|>" ascii wide
	$ = "<|LULUZPos|>" ascii wide
	$ = "<|LULUZRD|>" ascii wide
	$ = "<|LULUZRU|>" ascii wide
	$ = ">CRIAR_ALARME_AZUL<" ascii wide
	$ = ">ESCREVER_BOTAO_DIREITO<" ascii wide
	$ = ">REMOVER_ALARME_GRAY<" ascii wide
	$ = ">WIN_SETA_ACIMA<" ascii wide
	$ = ">WIN_SETA_BAIXO<" ascii wide
	$ = ">WIN_SETA_ESQUERDA<" ascii wide
	$ = "BOTAO_DIREITO" ascii wide

condition:
	5 of them
}
