rule LNKR_JS_a
{
meta:
	description = "Identifies LNKR, an aggressive adware that also performs clickjacking."
	author = "@bartblaze"
	date = "2021-04"
	tlp = "White"
	
strings:
	$ = "AMZN_SEARCH" ascii wide
	$ = "BANNER_LOAD" ascii wide
	$ = "CB_FSI_ANSWER" ascii wide
	$ = "CB_FSI_BLIND_NO_URL" ascii wide
	$ = "CB_FSI_BREAK" ascii wide
	$ = "CB_FSI_DISPLAY" ascii wide
	$ = "CB_FSI_DO_BLIND" ascii wide
	$ = "CB_FSI_ERROR_EXCEPTION" ascii wide
	$ = "CB_FSI_ERROR_PARSERESULT" ascii wide
	$ = "CB_FSI_ERROR_TIMEOUT" ascii wide
	$ = "CB_FSI_ERR_INVRELINDEX" ascii wide
	$ = "CB_FSI_ERR_INV_BLIND_POS" ascii wide
	$ = "CB_FSI_FUSEARCH" ascii wide
	$ = "CB_FSI_FUSEARCH_ORGANIC" ascii wide
	$ = "CB_FSI_INJECT_EMPTY" ascii wide
	$ = "CB_FSI_OPEN" ascii wide
	$ = "CB_FSI_OPTOUTED" ascii wide
	$ = "CB_FSI_OPTOUT_DO" ascii wide
	$ = "CB_FSI_ORGANIC_RESULT" ascii wide
	$ = "CB_FSI_ORGANIC_SHOW" ascii wide
	$ = "CB_FSI_ORGREDIR" ascii wide
	$ = "CB_FSI_SKIP" ascii wide
	$ = "MNTZ_INJECT" ascii wide
	$ = "MNTZ_LOADED" ascii wide
	$ = "OPTOUT_SHOW" ascii wide
	$ = "PROMO_ANLZ" ascii wide
	$ = "URL_IGNOREDOMAIN" ascii wide
	$ = "URL_STATICFILE" ascii wide

condition:
	5 of them
}

rule LNKR_JS_b
{
meta:
	description = "Identifies LNKR, an aggressive adware that also performs clickjacking."
	author = "@bartblaze"
	date = "2021-04"
	tlp = "White"
	
strings:
	$ = "StartAll ok" ascii wide
	$ = "dexscriptid" ascii wide
	$ = "dexscriptpopup" ascii wide
	$ = "rid=LAUNCHED" ascii wide
condition:
	3 of them
}

rule LNKR_JS_c
{
meta:
	description = "Identifies LNKR, an aggressive adware that also performs clickjacking."
	author = "@bartblaze"
	date = "2021-04"
	tlp = "White"
	
strings:
	$ = "var affid" ascii wide
	$ = "var alsotry_enabled" ascii wide
	$ = "var boot_time" ascii wide
	$ = "var checkinc" ascii wide
	$ = "var dom" ascii wide
	$ = "var fsgroup" ascii wide
	$ = "var gcheckrunning" ascii wide
	$ = "var kodom" ascii wide
	$ = "var last_keywords" ascii wide
	$ = "var trkid" ascii wide
	$ = "var uid" ascii wide
	$ = "var wcleared" ascii wide

condition:
	3 of them
}

rule LNKR_JS_d
{
meta:
	description = "Identifies LNKR, an aggressive adware that also performs clickjacking."
	author = "@bartblaze"
	date = "2021-04"
	tlp = "White"
	
strings:
	$ = "adTrack" ascii wide
	$ = "addFSBeacon" ascii wide
	$ = "addYBeacon" ascii wide
	$ = "algopopunder" ascii wide
	$ = "applyAdDesign" ascii wide
	$ = "applyGoogleDesign" ascii wide
	$ = "deleteElement" ascii wide
	$ = "fixmargin" ascii wide
	$ = "galgpop" ascii wide
	$ = "getCurrentKw" ascii wide
	$ = "getGoogleListing" ascii wide
	$ = "getParameterByName" ascii wide
	$ = "getXDomainRequest" ascii wide
	$ = "googlecheck" ascii wide
	$ = "hasGoogleListing" ascii wide
	$ = "insertAfter" ascii wide
	$ = "insertNext" ascii wide
	$ = "insertinto" ascii wide
	$ = "isGoogleNewDesign" ascii wide
	$ = "moreReq" ascii wide
	$ = "openInNewTab" ascii wide
	$ = "pagesurf" ascii wide
	$ = "replaceRel" ascii wide
	$ = "sendData" ascii wide
	$ = "sizeinc" ascii wide
	$ = "streamAds" ascii wide
	$ = "urlcleanup" ascii wide

condition:
	10 of them
}
