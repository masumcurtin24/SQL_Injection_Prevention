/*
  Real-world defensive rules (2026 refresh)
  Focus: LOLBAS abuse, script obfuscation, and phishing payload containers.
*/

rule lolbas_regsvr32_remote_scriptlet_2026
{
  meta:
    description = "Regsvr32 remote SCT execution pattern (Squiblydoo style)."
    author = "Security Team"
    threat_level = "High"
    category = "LOLBAS"
    reference = "https://lolbas-project.github.io/"
  strings:
    $exe = /regsvr32(\.exe)?/ nocase ascii wide
    $scrobj = "scrobj.dll" nocase ascii wide
    $remote_sct = /\/i:(https?:\/\/|\\\\)[^ \r\n\t]+\.sct/ nocase ascii wide
    $flags = "/s /n /u" nocase ascii wide
  condition:
    filesize < 700KB and $exe and $scrobj and $remote_sct and ($flags or #remote_sct >= 1)
}

rule lolbas_rundll32_js_mshtml_2026
{
  meta:
    description = "Rundll32 JavaScript/mshtml abuse pattern (Signed Binary Proxy Execution)."
    author = "Security Team"
    threat_level = "Critical"
    category = "LOLBAS"
    reference = "https://lolbas-project.github.io/"
  strings:
    $exe = /rundll32(\.exe)?/ nocase ascii wide
    $js = "javascript:" nocase ascii wide
    $mshtml = "mshtml,RunHTMLApplication" ascii wide
    $script1 = "GetObject(\"script:" ascii wide
    $script2 = "GetObject('script:" ascii wide
  condition:
    filesize < 700KB and $exe and $js and $mshtml and 1 of ($script*)
}

rule lolbas_mshta_remote_or_inline_script_2026
{
  meta:
    description = "MSHTA remote HTA or inline script execution indicator."
    author = "Security Team"
    threat_level = "High"
    category = "LOLBAS"
    reference = "https://lolbas-project.github.io/"
  strings:
    $exe = /mshta(\.exe)?/ nocase ascii wide
    $remote_hta = /https?:\/\/[^ \r\n\t\"']+\.hta/ nocase ascii wide
    $vbexec = "vbscript:Execute(" nocase ascii wide
    $js = "javascript:" nocase ascii wide
    $hta_tag = "<hta:application" nocase ascii wide
  condition:
    filesize < 1000KB and $exe and ( $remote_hta or ($vbexec and $js) or ($js and $hta_tag) )
}

rule lolbas_certutil_download_decode_2026
{
  meta:
    description = "Certutil download/decode abuse pattern."
    author = "Security Team"
    threat_level = "High"
    category = "LOLBAS"
    reference = "https://lolbas-project.github.io/"
  strings:
    $exe = /certutil(\.exe)?/ nocase ascii wide
    $urlcache = "-urlcache" nocase ascii wide
    $split = "-split" nocase ascii wide
    $force = " -f " nocase ascii wide
    $decode = "-decode" nocase ascii wide
    $http = /https?:\/\/[^\s\"']+/ nocase ascii wide
  condition:
    filesize < 1200KB and $exe and (
      ($urlcache and $http and ( $split or $force )) or
      ($decode and $http)
    )
}

rule suspicious_svg_ecmascript_base64_payload_2026
{
  meta:
    description = "Suspicious SVG carrying base64-encoded ECMAScript payload."
    author = "Security Team"
    threat_level = "Medium"
    category = "Phishing Payload"
    reference = "https://github.com/Neo23x0/signature-base"
  strings:
    $svg = "<svg" nocase ascii wide
    $script = "<script" nocase ascii wide
    $ecma = "data:application/ecmascript;base64," nocase ascii wide
    $b64 = /[A-Za-z0-9+\/]{120,}={0,2}/ ascii
  condition:
    filesize < 1000KB and $svg in (0..2048) and $script and $ecma and $b64
}

rule suspicious_js_obfuscatorio_structure_2026
{
  meta:
    description = "JavaScript obfuscator.io-like structure often used in malicious droppers."
    author = "Security Team"
    threat_level = "Medium"
    category = "Obfuscation"
    reference = "https://github.com/Neo23x0/signature-base"
  strings:
    $a1 = "var a0_0x" ascii
    $c1 = "while(!![])" ascii
    $c2 = "['atob']=function(" ascii
    $c3 = "{}.constructor(\\x22return\\x20this\\x22)(\\x20)" ascii
    $c4 = "return!![]" ascii
  condition:
    filesize < 1500KB and $a1 and 2 of ($c*)
}

rule suspicious_powershell_obfuscation_combo_2026
{
  meta:
    description = "Obfuscated PowerShell with execution/decode primitives."
    author = "Security Team"
    threat_level = "High"
    category = "PowerShell Abuse"
    reference = "https://github.com/Neo23x0/signature-base"
  strings:
    $ps_caret = /p[\^]?o[\^]?w[\^]?e[\^]?r[\^]?s[\^]?h[\^]?e[\^]?l[\^]?l/ nocase ascii wide
    $true1 = "${t`rue}" nocase ascii
    $true2 = "${tr`ue}" nocase ascii
    $true3 = "${t`r`u`e}" nocase ascii
    $fromb64 = "FromBase64String" nocase ascii wide
    $iex = /\biex\b|Invoke-Expression/ nocase ascii wide
    $enc = /-enc\s+[A-Za-z0-9+\/=]{40,}/ nocase ascii
  condition:
    filesize < 2000KB and (
      ($ps_caret and 1 of ($fromb64, $iex, $enc)) or
      (1 of ($true*) and 1 of ($fromb64, $iex, $enc))
    )
}

rule suspicious_pipe_to_shell_download_exec_2026
{
  meta:
    description = "Download-and-execute one-liner patterns (curl/wget/powershell)."
    author = "Security Team"
    threat_level = "High"
    category = "Command Injection"
    reference = "https://attack.mitre.org/"
  strings:
    $curl_pipe = /curl\s+(-[A-Za-z]+\s+){0,3}(https?:\/\/|hxxps?:\/\/)[^\r\n|]{1,220}\|\s*(bash|sh)\b/ nocase ascii
    $wget_pipe = /wget\s+(-[A-Za-z]+\s+){0,3}(https?:\/\/|hxxps?:\/\/)[^\r\n|]{1,220}\|\s*(bash|sh)\b/ nocase ascii
    $ps_pipe = /powershell(\.exe)?\s+[^\r\n]{0,250}(invoke-webrequest|iwr)[^\r\n]{0,250}\|\s*iex/ nocase ascii
  condition:
    filesize < 800KB and 1 of them
}
