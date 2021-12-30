rule Ganelp
{
meta:
	description = "Identifies Ganelp, a worm that also spreads via USB."
	author = "@bartblaze"
	date = "2021-06-01"
	tlp = "White"

strings:
	$ = "regardez cette photo :D %s" ascii wide
	$ = "to fotografiu :D %s" ascii wide
	$ = "vejte se na mou fotku :D %s" ascii wide
	$ = "bekijk deze foto :D %s" ascii wide
	$ = "spojrzec na to zdjecie :D %s" ascii wide
	$ = "bu resmi bakmak :D %s" ascii wide
	$ = "dette bildet :D %s" ascii wide
	$ = "seen this?? :D %s" ascii wide
	$ = "guardare quest'immagine :D %s" ascii wide
	$ = "denna bild :D %s" ascii wide
	$ = "olhar para esta foto :D %s" ascii wide
	$ = "uita-te la aceasta fotografie :D %s" ascii wide
	$ = "pogledaj to slike :D %s" ascii wide
	$ = "poglej to fotografijo :D %s" ascii wide
	$ = "dette billede :D %s" ascii wide

condition:
	3 of them
}
