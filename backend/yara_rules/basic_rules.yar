/*

    PROFESSIONAL YARA RULESET

    Version: 3.1 (Corrected)

    Description: A dynamic, weighted ruleset for detecting a broad range of web-based

    threats, including webshells, command injection, reverse shells, and obfuscated code.
    */

rule webshell_indicators_php
{
meta:
description = "Detects high-confidence indicators of PHP webshells by looking for combinations of suspicious functions."
author = "Security Analyst"
threat_level = "High"
category = "Webshell"
strings:
$exec_func1 = "system("
$exec_func2 = "passthru("
$exec_func3 = "shell_exec("
$code_eval = "eval("
$file_write = "file_put_contents"

condition:
    1 of ($exec_func*) and 1 of ($code_eval, $file_write)

}

rule potential_obfuscation
{
meta:
description = "Detects common code obfuscation patterns used to hide malicious payloads."
author = "Security Analyst"
threat_level = "Medium"
category = "Obfuscation"
strings:
$b64 = "base64_decode"
$eval = "eval("
$gz = "gzinflate"

condition:
    ($b64 or $gz) and $eval

}

rule command_injection_and_reverse_shell_indicators
{
meta:
description = "Detects a wide range of commands and patterns associated with OS command injection and reverse shells."
author = "Security Analyst"
threat_level = "Critical"
category = "Command Injection"
strings:
// --- High-Confidence Reverse Shell Patterns ---
$rev_sh1 = "/bin/sh -i"
$rev_sh2 = "bash -i"
$rev_sh3 = "mkfifo"
$rev_py = "python -c 'import socket"
$rev_pl = "perl -MIO"

    // --- Common Attacker Tools ---
    $tool1 = "nc " // Netcat
    $tool2 = "wget "
    $tool3 = "curl "

    // --- Suspicious Structures ---
    $struct1 = "|nc"
    $struct2 = "|/bin/sh"

condition:
    // CORRECTED LOGIC: This condition now correctly references all defined strings.
    // It triggers if any high-confidence reverse shell pattern is found, OR
    // if a combination of an attacker tool and a suspicious structure is found.
    1 of ($rev_sh1, $rev_sh2, $rev_sh3, $rev_py, $rev_pl) or (1 of ($tool*) and 1 of ($struct*))

}

rule office_macro_suspicious
{
meta:
description = "Detects suspicious VBA macro auto-execution and shelling patterns in Office documents."
author = "Security Analyst"
threat_level = "High"
category = "Office Macro"
strings:
$auto1 = "AutoOpen"
$auto2 = "Document_Open"
$auto3 = "AutoExec"
$wscript = "WScript.Shell"
$createobj = "CreateObject(\"WScript.Shell\")"
$cmd = "cmd.exe"
$ps = "powershell"
$environ = "Environ("
condition:
    (1 of ($auto*)) and (1 of ($wscript, $createobj, $cmd, $ps, $environ))
}

rule pdf_suspicious_actions
{
meta:
description = "Detects suspicious PDF actions like JavaScript, OpenAction, Launch, and embedded files."
author = "Security Analyst"
threat_level = "Medium"
category = "PDF"
strings:
$js1 = "/JS"
$js2 = "/JavaScript"
$aa = "/AA"
$open = "/OpenAction"
$launch = "/Launch"
$embed = "/EmbeddedFile"
$acro = "/AcroForm"
$rich = "/RichMedia"
condition:
    2 of ($js*, $aa, $open, $launch, $embed, $acro, $rich) or ($open and 1 of ($js*, $launch))
}


/* --- Exploit/PoC Indicators (Appended) --- */

rule exploit_poc_generic_edb_cve
{
meta:
description = "Exploit/PoC write-up indicators (Exploit-DB + CVE)."
author = "Security Analyst"
threat_level = "Medium"
category = "Exploit PoC"
strings:
$edb1 = "Exploit Database" nocase ascii wide
$edb2 = "EDB-ID:" nocase ascii wide
$title = "Exploit-Title:" nocase ascii wide
$cve   = /CVE-\d{4}-\d{4,7}/ nocase ascii wide
condition:
    $edb1 and ($edb2 or $title) and $cve
}

rule exploit_poc_phpmyadmin_bruteforce
{
meta:
description = "phpMyAdmin brute-force PoC (Exploit-DB style + Python urllib/cookiejar)."
author = "Security Analyst"
threat_level = "High"
category = "Exploit PoC"
reference = "CVE-2015-6830"
strings:
$app    = "phpMyAdmin" nocase ascii wide
$pma1   = "pma_username" ascii wide
$pma2   = "pma_password" ascii wide
$py1    = "urllib.request" ascii
$py2    = "urllib.parse" ascii
$py3    = "http.cookiejar" ascii
$py4    = "threading" ascii
$logout = "index.php?route=/logout" ascii
condition:
    $app and ( 2 of ( $pma1, $pma2, $py1, $py2, $py3, $py4, $logout ) )
}

// Broader PoC/Exploit indicators (tools + CVE/EDB context)
rule exploit_poc_generic_tools
{
meta:
description = "Generic exploit PoC indicators: GHDB/SearchSploit/OffSec banners + CVE."
author = "Security Analyst"
threat_level = "Medium"
category = "Exploit PoC"
strings:
$ghdb   = "GHDB" nocase ascii wide
$ss     = "SearchSploit" nocase ascii wide
$offsec = "Exploit Database by OffSec" nocase ascii wide
$offsec2= "OffSec Services Limited" nocase ascii wide
$cve    = /CVE-\d{4}-\d{4,7}/ nocase ascii wide
condition:
    (1 of ($ghdb, $ss, $offsec, $offsec2)) and $cve
}

rule exploit_poc_python_generic
{
meta:
description = "Python PoC scaffold with CVE/Exploit context (requests/urllib + argv)."
author = "Security Analyst"
threat_level = "Medium"
category = "Exploit PoC"
strings:
$req = "import requests" ascii
$url = "urllib.request" ascii
$argv = "sys.argv" ascii
$expl = /Exploit(\s|-)?Title:/ nocase ascii wide
$cve  = /CVE-\d{4}-\d{4,7}/ nocase ascii wide
condition:
    ( ($req or $url) and $argv ) and ($cve or $expl)
}

rule exploit_poc_bruteforce_generic
{
meta:
description = "Generic brute PoC markers (threading/cookiejar + login fields) with CVE/EDB context."
author = "Security Analyst"
threat_level = "High"
category = "Exploit PoC"
strings:
$thr = "threading" ascii
$cj  = "http.cookiejar" ascii
$usr = /user(name)?/ nocase ascii wide
$pwd = /pass(word)?/ nocase ascii wide
$cve = /CVE-\d{4}-\d{4,7}/ nocase ascii wide
$edb = "Exploit Database" nocase ascii wide
condition:
    ( ($thr or $cj) and ($usr or $pwd) ) and ($cve or $edb)
}

rule exploit_poc_powershell_downloader
{
meta:
description = "PowerShell download/execute PoC (IEX + WebClient/DownloadString, -enc)."
author = "Security Analyst"
threat_level = "High"
category = "Exploit PoC"
strings:
$ps1 = /powershell(\.exe)?/ nocase ascii wide
$iex = /\bIEX\b|Invoke-Expression/ nocase ascii wide
$dl1 = "DownloadString" ascii wide
$wc  = "System.Net.WebClient" ascii wide
$enc = /-enc\s+[A-Za-z0-9+\/=]{20,}/ nocase ascii
$fb64= "FromBase64String" ascii wide
$cve = /CVE-\d{4}-\d{4,7}/ nocase ascii wide
condition:
    $ps1 and ( ($iex and ($dl1 or $wc or $fb64)) or $enc ) and ($cve or filesize < 300000)
}

rule exploit_poc_metasploit_module
{
meta:
description = "Metasploit module-style Ruby code with exploit scaffolding."
author = "Security Analyst"
threat_level = "Medium"
category = "Exploit PoC"
strings:
$msf1 = "Msf::Exploit" ascii
$msf2 = "include Msf::Exploit::Remote" ascii
$targ = "Targets =>" ascii
$opts = "register_options" ascii
$dis  = "DisclosureDate" ascii
condition:
    2 of ($msf*) and 1 of ($targ, $opts, $dis)
}

rule exploit_poc_python_pwntools
{
meta:
description = "Python PoC using pwntools/ROP/ELF patterns (CTF/exploit style)."
author = "Security Analyst"
threat_level = "Medium"
category = "Exploit PoC"
strings:
$pwn = "from pwn import *" ascii
$elf = "ELF(" ascii
$rop = "ROP(" ascii
$ctx = "context.arch" ascii
$cve = /CVE-\d{4}-\d{4,7}/ nocase ascii wide
condition:
    ($pwn or $elf or $rop or $ctx) and ($cve or filesize < 500000)
}

rule exploit_poc_js_fetch_xhr
{
meta:
description = "JavaScript PoC with HTTP primitives and CVE/Exploit context."
author = "Security Analyst"
threat_level = "Medium"
category = "Exploit PoC"
strings:
$xhr = "XMLHttpRequest" ascii
$fet = "fetch(" ascii
$ax  = "ActiveXObject" ascii
$cve = /CVE-\d{4}-\d{4,7}/ nocase ascii wide
$exp = /Exploit(\s|-)?Title:/ nocase ascii wide
condition:
    (1 of ($xhr, $fet, $ax)) and (1 of ($cve, $exp))
}

rule exploit_poc_generic_poc_terms
{
meta:
description = "Generic PoC terms with code presence."
author = "Security Analyst"
threat_level = "Medium"
category = "Exploit PoC"
strings:
$poc1 = /Proof[ -]?of[ -]?Concept/ nocase ascii wide
$poc2 = /\bPoC\b/ nocase ascii wide
$code = /(import\s+|function\s+|def\s+|class\s+|var\s+|let\s+)/ nocase ascii
condition:
    1 of ($poc*) and $code
}

rule obfuscation_base64_large_generic
{
meta:
description = "Large base64-like blobs combined with eval/execute primitives (generic)."
author = "Security Analyst"
threat_level = "Medium"
category = "Obfuscation"
strings:
$b64blob = /[A-Za-z0-9+\/]{80,}={0,2}/ ascii
$js_eval = "eval(" ascii
$js_atob = "atob(" ascii
$ps_iex = /\bIEX\b|Invoke-Expression/ ascii nocase
$ps_fb64 = "FromBase64String" ascii
$php_eval = "eval(" ascii
condition:
    $b64blob and ( $js_eval or $js_atob or $ps_iex or $ps_fb64 or $php_eval )
}


rule exploit_poc_writeup_generic
{
meta:
description = "Exploit write-up indicators (Exploit Title and/or PoC with CVE) without requiring code."
author = "Security Analyst"
threat_level = "Medium"
category = "Exploit PoC"
strings:
$exp_title = "Exploit Title:" nocase ascii
$poc_word  = "PoC" nocase ascii wide
$cve_tag   = /CVE-\d{4}-\d{4,7}/ nocase ascii wide
condition:
    $cve_tag and ( $exp_title or $poc_word )
}

rule exploit_advisory_asan_generic
{
meta:
description = "Exploit advisory write-up with ASAN evidence and structured sections (Description/Test script/Expected/Actual)."
author = "Security Analyst"
threat_level = "Medium"
category = "Exploit PoC"
strings:
$desc = "Description:" nocase ascii
$test = "Test script:" nocase ascii
$exp  = "Expected result:" nocase ascii
$act  = "Actual result:" nocase ascii
$asan = "AddressSanitizer:" ascii nocase
$sbo  = "stack-buffer-overflow" ascii nocase
condition:
    $asan and ( $sbo or 2 of ($desc,$test,$exp,$act) )
}
rule powershell_tcp_socket_shell
{
meta:
description = "Detects PowerShell TCP listener/client shells that accept remote input and execute commands."
author = "Security Analyst"
threat_level = "Critical"
category = "Remote Shell"
strings:
$listener = "System.Net.Sockets.TcpListener" nocase ascii wide
$client = "System.Net.Sockets.TcpClient" nocase ascii wide
$accept = "AcceptTcpClient" nocase ascii wide
$connect = ".Connect(" nocase ascii wide
$stream = "GetStream" nocase ascii wide
$iex1 = /\biex\b/ nocase ascii wide
$iex2 = "Invoke-Expression" nocase ascii wide
$ascii1 = "System.Text.ASCIIEncoding" nocase ascii wide
$ascii2 = "[text.encoding]::ASCII" nocase ascii wide
condition:
    1 of ($listener, $client) and 1 of ($accept, $connect) and $stream and 1 of ($iex*) and 1 of ($ascii*)
}