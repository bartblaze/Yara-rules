rule RedLine_a
{
    meta:
        id = "4Eeg9my5Llk67wiTDuBhLS"
        fingerprint = "8ba3c33d3affea6488b4fc056ad672922e243c790f16695bcf27c6dfab4ec611"
        version = "1.0"
        creation_date = "2021-06-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies RedLine stealer."
        category = "MALWARE"
        malware = "REDLINE"
        malware = "INFOSTEALER"

    strings:
        $ = "Account" ascii wide
        $ = "AllWalletsRule" ascii wide
        $ = "ArmoryRule" ascii wide
        $ = "AtomicRule" ascii wide
        $ = "Autofill" ascii wide
        $ = "BrowserExtensionsRule" ascii wide
        $ = "BrowserVersion" ascii wide
        $ = "Chrome" ascii wide
        $ = "CoinomiRule" ascii wide
        $ = "CommandLineUpdate" ascii wide
        $ = "CryptoHelper" ascii wide
        $ = "CryptoProvider" ascii wide
        $ = "DataBaseConnection" ascii wide
        $ = "DesktopMessangerRule" ascii wide
        $ = "DiscordRule" ascii wide
        $ = "DisplayHelper" ascii wide
        $ = "DownloadAndExecuteUpdate" ascii wide
        $ = "DownloadUpdate" ascii wide
        $ = "ElectrumRule" ascii wide
        $ = "EndpointConnection" ascii wide
        $ = "EthRule" ascii wide
        $ = "ExodusRule" ascii wide
        $ = "Extensions" ascii wide
        $ = "FileCopier" ascii wide
        $ = "FileScanner" ascii wide
        $ = "FileScannerArg" ascii wide
        $ = "FileScannerRule" ascii wide
        $ = "FileZilla" ascii wide
        $ = "GameLauncherRule" ascii wide
        $ = "Gecko" ascii wide
        $ = "GeoHelper" ascii wide
        $ = "GeoInfo" ascii wide
        $ = "GeoPlugin" ascii wide
        $ = "GuardaRule" ascii wide
        $ = "HardwareType" ascii wide
        $ = "IpSb" ascii wide
        $ = "IRemoteEndpoint" ascii wide
        $ = "ITaskProcessor" ascii wide
        $ = "JaxxRule" ascii wide
        $ = "NordApp" ascii wide
        $ = "OpenUpdate" ascii wide
        $ = "OpenVPNRule" ascii wide
        $ = "OsCrypt" ascii wide
        $ = "Program" ascii wide
        $ = "ProgramMain" ascii wide
        $ = "ProtonVPNRule" ascii wide
        $ = "RecordHeaderField" ascii wide
        $ = "RecoursiveFileGrabber" ascii wide
        $ = "ResultFactory" ascii wide
        $ = "ScanDetails" ascii wide
        $ = "ScannedBrowser" ascii wide
        $ = "ScannedCookie" ascii wide
        $ = "ScannedFile" ascii wide
        $ = "ScanningArgs" ascii wide
        $ = "ScanResult" ascii wide
        $ = "SqliteMasterEntry" ascii wide
        $ = "StringDecrypt" ascii wide
        $ = "SystemHardware" ascii wide
        $ = "SystemInfoHelper" ascii wide
        $ = "TableEntry" ascii wide
        $ = "TaskResolver" ascii wide
        $ = "UpdateAction" ascii wide
        $ = "UpdateTask" ascii wide
        $ = "XMRRule" ascii wide

    condition:
        45 of them
}

rule RedLine_b
{
    meta:
        id = "6Ds02SHJ9xqDC5ehVb5PEZ"
        fingerprint = "5ecb15004061205cdea7bcbb6f28455b6801d82395506fd43769d591476c539e"
        version = "1.0"
        creation_date = "2021-10-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies RedLine stealer."
        category = "MALWARE"

    strings:
        $ = "Account" ascii wide
        $ = "AllWallets" ascii wide
        $ = "Autofill" ascii wide
        $ = "Browser" ascii wide
        $ = "BrowserVersion" ascii wide
        $ = "Chr_0_M_e" ascii wide
        $ = "CommandLineUpdate" ascii wide
        $ = "ConfigReader" ascii wide
        $ = "DesktopMessanger" ascii wide
        $ = "Discord" ascii wide
        $ = "DownloadAndExecuteUpdate" ascii wide
        $ = "DownloadUpdate" ascii wide
        $ = "EndpointConnection" ascii wide
        $ = "Extensions" ascii wide
        $ = "FileCopier" ascii wide
        $ = "FileScanner" ascii wide
        $ = "FileScannerArg" ascii wide
        $ = "FileScanning" ascii wide
        $ = "FileSearcher" ascii wide
        $ = "FileZilla" ascii wide
        $ = "FullInfoSender" ascii wide
        $ = "GameLauncher" ascii wide
        $ = "GdiHelper" ascii wide
        $ = "GeoInfo" ascii wide
        $ = "GeoPlugin" ascii wide
        $ = "HardwareType" ascii wide
        $ = "IContract" ascii wide
        $ = "ITaskProcessor" ascii wide
        $ = "IdentitySenderBase" ascii wide
        $ = "LocalState" ascii wide
        $ = "LocatorAPI" ascii wide
        $ = "NativeHelper" ascii wide
        $ = "NordApp" ascii wide
        $ = "OpenUpdate" ascii wide
        $ = "OpenVPN" ascii wide
        $ = "OsCrypt" ascii wide
        $ = "ParsSt" ascii wide
        $ = "PartsSender" ascii wide
        $ = "RecordHeaderField" ascii wide
        $ = "ScanDetails" ascii wide
        $ = "ScanResult" ascii wide
        $ = "ScannedCookie" ascii wide
        $ = "ScannedFile" ascii wide
        $ = "ScanningArgs" ascii wide
        $ = "SenderFactory" ascii wide
        $ = "SqliteMasterEntry" ascii wide
        $ = "StringDecrypt" ascii wide
        $ = "SystemHardware" ascii wide
        $ = "SystemInfoHelper" ascii wide
        $ = "TableEntry" ascii wide
        $ = "TaskResolver" ascii wide
        $ = "UpdateAction" ascii wide
        $ = "UpdateTask" ascii wide
        $ = "WalletConfig" ascii wide

    condition:
        45 of them
}

import "dotnet"

rule RedLine_Campaign_June2021
{
    meta:
        id = "6obnDftS8HPC8ATVxov3ol"
        fingerprint = "4f389cf9f0343eb0e526c25f0beea9a0b284e96029dc064e85557ae2fe8bdf9d"
        version = "1.0"
        creation_date = "2021-06-01"
        first_imported = "2021-12-30"
        last_modified = "2021-12-30"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies RedLine stealer's June 2021 campaign."
        category = "MALWARE"
        reference = "https://bartblaze.blogspot.com/2021/06/digital-artists-targeted-in-redline.html"


    condition:
        dotnet.guids[0]=="a862cb90-79c7-41a9-847b-4ce4276feaeb" or dotnet.guids[0]=="a955bdf8-f5ac-4383-8f5d-a4111125a40e" or dotnet.guids[0]=="018ca516-2128-434a-b7c6-8f9a75dfc06e" or dotnet.guids[0]=="829c9056-6c93-42c2-a9c8-19822ccac0a4" or dotnet.guids[0]=="e1a702b0-dee1-463a-86d3-e6a9aa86348e" or dotnet.guids[0]=="6152d28b-1775-47e6-902f-8bdc9e2cb7ca" or dotnet.guids[0]=="111ab36c-09ad-4a3e-92b3-a01076ce68e0" or dotnet.guids[0]=="ea7dfb6d-f951-48e6-9e25-41c31080fd42" or dotnet.guids[0]=="34bca13d-abb5-49ce-8333-052ec690e01e" or dotnet.guids[0]=="1422b4dd-c4c1-4885-b204-200e83267597" or dotnet.guids[0]=="d0570d65-3998-4954-ab42-13b122f7dde5"
}