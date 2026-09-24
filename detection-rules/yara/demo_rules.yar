/*
 * SENTIVRA — starter YARA rule pack (detection-rules/yara/)
 *
 * Rules are stored separately from application code (brief §11 applies the
 * same principle to Sigma; the same separation is used for YARA). This
 * pack is intentionally small and demonstration-focused — it is not a
 * substitute for a maintained commercial/community signature feed, and
 * Sentivra never claims otherwise (see docs/threat-model.md, MalwareDetector
 * limitations).
 */

rule EICAR_Test_File
{
    meta:
        description = "Detects the EICAR antivirus test string — a standard, harmless test file, not real malware"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
        severity = "LOW"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_PowerShell_Obfuscation
{
    meta:
        description = "PowerShell invoked with EncodedCommand and/or ExecutionPolicy Bypass — a common obfuscation/evasion pattern, not proof of malice on its own"
        severity = "MEDIUM"
    strings:
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-enc " nocase
        $bypass = "-ExecutionPolicy Bypass" nocase
        $hidden = "-WindowStyle Hidden" nocase
        $downloadstring = "DownloadString(" nocase
    condition:
        2 of them
}

rule Office_Macro_AutoOpen_Suspicious
{
    meta:
        description = "Office document macro using AutoOpen/Document_Open combined with shell execution — classic maldoc pattern"
        severity = "HIGH"
    strings:
        $auto1 = "AutoOpen" nocase
        $auto2 = "Document_Open" nocase
        $shell1 = "Shell(" nocase
        $shell2 = "WScript.Shell" nocase
        $shell3 = "CreateObject" nocase
    condition:
        (1 of ($auto*)) and (1 of ($shell*))
}

rule JavaScript_Obfuscated_Eval
{
    meta:
        description = "JavaScript/HTML using eval+unescape/fromCharCode chains typical of obfuscated droppers embedded in HTML/SVG"
        severity = "MEDIUM"
    strings:
        $eval = "eval(" nocase
        $unescape = "unescape(" nocase
        $fromcharcode = "fromCharCode(" nocase
    condition:
        $eval and (1 of ($unescape, $fromcharcode))
}
