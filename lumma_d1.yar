/*
   Lumma Stealer (+ ClickFix delivery chains)  |  YARA rules
   Generated: 2026-11-02
   Basis: public reporting only (Huntress 2026-10-21, Microsoft/THN 2026-03-06, Bitdefender 2026-02-11).
   IMPORTANT: no real Lumma binary was analysed. Public reports in this window publish
   infrastructure and behaviour, not code strings. Rules 1-2 are infrastructure/lure based;
   rule 3 is built from background knowledge of Lumma's C2 protocol and must be validated
   against a real sample before deployment.
*/

rule ClickFix_Lure_Finger_Command_Clipboard
{
    meta:
        description = "Fake CAPTCHA/verification page that places a 'finger user@host' command (including caret/comma-obfuscated forms) on the clipboard and tells the user to paste it in Run."
        author      = "Detection Engineering"
        date        = "2026-11-02"
        reference   = "https://huntress.com/blog/amazon-clickfix-finger"
        mitre       = "T1204.004, T1218"
        confidence  = "medium"
        limitation  = "Misses lures that build the command at runtime from encoded parts."

    strings:
        $clip1 = "navigator.clipboard.writeText" ascii
        $clip2 = "execCommand(\"copy\")" ascii
        $clip3 = "execCommand('copy')" ascii
        $ver1  = "i'm not a robot" ascii nocase
        $ver2  = "verify you are human" ascii nocase
        $ver3  = "not a robot" ascii nocase
        $fing  = /f[\^,_\-]{0,2}i[\^,_\-]{0,2}n[\^,_\-]{0,2}g[\^,_\-]{0,2}e[\^,_\-]{0,2}r[\^\s,_\-]{1,6}[A-Za-z0-9]{4,20}@[a-z0-9\-\.]{4,}/ nocase ascii
        $run1  = "Win + R" ascii nocase
        $run2  = "Win+R" ascii nocase
        $run3  = "Windows + R" ascii nocase

    condition:
        filesize < 3MB and 1 of ($clip*) and 1 of ($ver*) and $fing and 1 of ($run*)
}

rule Lumma_ClickFix_Campaign_Infra_Oct2026
{
    meta:
        description = "Scripts, memory or logs referencing the Oct-2026 Amazon-themed ClickFix infrastructure and staging artifacts (timer6 / v6 / sqr-viewertr6, NodeView, Prodclear). Huntress attributes the stealer only as 'allegedly Lumma'."
        author      = "Detection Engineering"
        date        = "2026-11-02"
        reference   = "https://huntress.com/blog/amazon-clickfix-finger"
        mitre       = "T1105, T1055"
        confidence  = "medium"
        limitation  = "Infrastructure-based: short shelf life; domains can be rotated."

    strings:
        $d1 = "grillmasterchef.com" ascii wide nocase
        $d2 = "kiriosyka.com" ascii wide nocase
        $d3 = "liokida.com" ascii wide nocase
        $d4 = "grillrecipespro.com" ascii wide nocase
        $d5 = "perfectgrillrecipes.com" ascii wide nocase
        $d6 = "thegrilljournal.com" ascii wide nocase
        $d7 = "homelygrill.com" ascii wide nocase
        $d8 = "embersandbites.com" ascii wide nocase
        $s1 = "sqr-viewertr6" ascii wide
        $s2 = "ProgramData\\NodeView" ascii wide nocase
        $s3 = "ProgramData\\Prodclear" ascii wide nocase
        $s4 = "ipyw32.exe" ascii wide nocase
        $ip = "167.148.201.106" ascii wide

    condition:
        filesize < 10MB and ( 1 of ($d*) or $s1 or $ip or 2 of ($s2, $s3, $s4) )
}

rule Lumma_C2_Protocol_Strings_LOW_CONFIDENCE
{
    meta:
        description = "Generic Lumma C2 request-format strings (act= action codes, lid= build/affiliate id, ver=). Built from analyst background knowledge of Lumma network protocol, NOT from a sample or from the reports gathered for this task."
        author      = "Detection Engineering"
        date        = "2026-11-02"
        confidence  = "low"
        limitation  = "VALIDATE against a known Lumma sample before deploying. Newer builds (v5/v6) may have changed the format. Intended for memory/unpacked-PE scanning, not packed on-disk files."

    strings:
        $act1 = "act=receive_message" ascii wide
        $act2 = "act=life" ascii wide
        $lid  = "lid=" ascii wide
        $ver  = "&ver=" ascii wide
        $j    = "&j=" ascii wide

    condition:
        uint16(0) == 0x5A4D and filesize < 5MB and 1 of ($act*) and $lid and ( $ver or $j )
}
