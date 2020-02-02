rule HMining_Binary_A
{
    meta:
        description = "OSX.HMining.A"

    strings:
        $a = {68 69 64 65 4F 70 65 72 61 74 6F 72 57 69 64 6F 77 41 66 74 65 72 41 64 6D 69 6E}
        $b = {48 8B 85 98 FE FF FF 48 89 44 24 38 48 8B 85 90 FE FF FF 48 89 44 24 30 48 8B 85 80 FE FF FF 48 8B 8D 88 FE FF FF 48 89 4C 24 28 48 89 44 24 20 48 8B 85 00 FF FF FF 48 89 44 24 18 48 8B 85 F8 FE FF FF 48 89 44 24 10 48 8B 85 E8 FE FF FF 48 8B 8D F0 FE FF FF 48 89 4C 24 08 48 89 04 24}
        $c = {61 6C 6C 43 6F 6D 70 65 74 69 74 6F 72 73 41 67 65 6E 74 44 65 6D 6F 6E 64}
        $d = {63 72 65 61 74 65 41 6E 64 4C 6F 61 64 41 67 65 6E 74 50 6C 69 73 74 50 61 74 68 3A 61 67 65 6E 74 50 6C 69 73 74 4E 61 6D 65 3A 61 67 65 6E 74 50 6C 69 73 74 4B 65 79 41 72 72 3A 61 67 65 6E 74 50 6C 69 73 74 56 61 6C 41 72 72 3A 69 73 41 64 6D 69 6E 3A}
    condition:
        ($a and $b) or ($c and $d)
}

rule TroviProxyApp
{
	meta:
        description = "OSX.Trovi.A"
    strings:
        $a = {72 65 63 65 69 76 69 6E 67 57 65 62 73 69 74 65 53 74 61 72 74 65 64}
        $b = {68 74 6D 6C 49 6E 6A 65 63 74 65 64}
    condition:
		($a and $b)
}

rule HMining
{
    meta:
        description = "OSX.Hmining.A"
    strings:
        $a = {68 69 64 65 4F 70 65 72 61 74 6F 72 57 69 64 6F 77 41 66 74 65 72 41 64 6D 69 6E}
        $b = {48 8B 85 98 FE FF FF 48 89 44 24 38 48 8B 85 90 FE FF FF 48 89 44 24 30 48 8B 85 80 FE FF FF 48 8B 8D 88 FE FF FF 48 89 4C 24 28 48 89 44 24 20 48 8B 85 00 FF FF FF 48 89 44 24 18 48 8B 85 F8 FE FF FF 48 89 44 24 10 48 8B 85 E8 FE FF FF 48 8B 8D F0 FE FF FF 48 89 4C 24 08 48 89 04 24}
    condition:
        ($a and $b)
}


rule BundloreA
{
    meta:
        description = "OSX.Bundlore.A"
    strings:
        $a = {5F 5F 6D 6D 5F 67 65 74 49 6E 6A 65 63 74 65 64 50 61 72 61 6D 73}
        $b = {5F 5F 6D 6D 5F 72 75 6E 53 68 65 6C 6C 53 63 72 69 70 74 41 73 52 6F 6F 74}
    condition:
        ($a and $b)
}

rule GenieoE
{
    meta:
        description = "OSX.Genieo.E"
    strings:
        $a = {47 4E 53 69 6E 67 6C 65 74 6F 6E 47 6C 6F 62 61 6C 43 61 6C 63 75 6C 61 74 6F 72}
        $b = {47 4E 46 61 6C 6C 62 61 63 6B 52 65 70 6F 72 74 48 61 6E 64 6C 65 72}
    condition:
        ($a and $b)
}

rule InstallCoreA
{
    
    meta:
        description = "OSX.InstallCore.A"
    strings:
        $a = {C6 45 A0 65 C6 45 A1 52 C6 45 A2 4A C6 45 A3 50 C6 45 A4 5B C6 45 A5 57 C6 45 A6 72 C6 45 A7 48 C6 45 A8 53 C6 45 A9 5D C6 45 AA 25 C6 45 AB 33 C6 45 AC 42 C6 45 A0 53 B8 01 00 00 00}
        $b = {49 89 DF 48 89 C3 FF D3 4C 89 EF FF D3 48 8B 7D B0 FF D3 48 8B 7D B8 FF D3 4C 89 FF FF D3 4C 8B 6D C0 48 8B 7D A8}
        $c = {49 43 4A 61 76 61 53 63 72 69 70 74 45 6E 76 69 72 6F 6E 6D 65 6E 74 49 6E 66 6F}
    condition:
        ($a or $b or $c)
}


rule KeRangerA
{
    meta:
        description = "OSX.KeRanger.A"

    strings:
        $a = {48 8D BD D0 EF FF FF BE 00 00 00 00 BA 00 04 00 00 31 C0 49 89 D8 ?? ?? ?? ?? ?? 31 F6 4C 89 E7 ?? ?? ?? ?? ?? 83 F8 FF 74 57 C7 85 C4 EB FF FF 00 00 00 00}

    condition:
        $a
}

rule CrossRiderA
{
	meta:
		description="OSX.CrossRider.A"
	strings:
		$a = {E9 00 00 00 00 48 8B 85 00 FE FF FF 8A 08 88 8D 5F FE FF FF 0F BE 95 5F FE FF FF 83 C2 D0 89 55 E0 48 8B B5 60 FE FF FF 48 8B BD 40 FE FF FF}
	condition:
		$a
}


rule GenieoDropper
{
    meta:
        description = "OSX.GenieoDropper.A"
    strings:
        $a = {66756E6374696F6E204163636570744F666665727328297B}
        $b = {747261636B416E616C79746963734576656E742822657865637574696F6E222C224A7352756E22293B}
    condition:
        $a and $b
}

rule XcodeGhost
{
    meta:
        description = "OSX.XcodeGhost.A"
    strings:
        $a = {8346002008903046 [-] 082108A800910021019101210296032203955346CDF810B0059406900120}
        $b = {8346002007902046 [-] 082107A8009100210DF10409032289E8320801214346059606900120}
        $c = {8346002007903046 [-] 082107A800910021019101210296032203955346CDF810B0059406900020}
    condition:
        ($a or $b or $c)
}

rule GenieoD
{
    meta:
        description = "OSX.Genieo.D"
    strings:
        $a = {49 89 C4 0F 57 C0 0F 29 85 80 FE FF FF 0F 29 85 70 FE FF FF 0F 29 85 60 FE FF FF 0F 29 85 50 FE FF FF 41 B8 10 00 00 00 4C 89 E7 48 8B B5 40 FE FF FF 48 8D 95 50 FE FF FF 48}
        $b = {F2 0F 59 C1 F2 0F 5C D0 F2 0F 11 55 B8 0F 28 C2 F2 0F 10 55 D8 F2 0F 10 5D C8 F2 0F 58 DA F2 0F 59 D1 F2 0F 5C DA F2 0F 11 5D B0 0F 28 CB 31 FF BE 05 00 00 00 31 D2}
        $c = {49 6E 73 74 61 6C 6C 4D 61 63 41 70 70 44 65 6C 65 67 61 74 65}
    condition:
        ($a or $b) and $c
}