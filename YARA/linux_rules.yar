rule LINUX_Exfil_Wiper_Healthcheck_Signature
{
  meta:
    description = "Detects attacker 'healthcheck' script behavior and signature string H4ck3rM4n"
    ioc_type = "filename + behavior strings"
    confidence = "high_if_script_matches"
    note = "Run on scripts, crontabs, /etc, /var/www artifacts, triage bundles"

  strings:
    $name = "healthcheck" nocase
    $sig  = "H4ck3rM4n"

    // Targeted directories from IOC
    $d1 = "/etc"
    $d2 = "/home"
    $d3 = "/var/www"
    $d4 = "/root"

    // Deletion/exfil primitives (generic but useful in combination)
    $rm1 = "rm -rf" nocase
    $tar = "tar " nocase
    $curl = "curl " nocase
    $wget = "wget " nocase
    $scp  = "scp " nocase
    $nc   = "nc " nocase

  condition:
    $sig or
    (
      $name and 2 of ($d*) and
      (1 of ($rm1, $tar) and 1 of ($curl, $wget, $scp, $nc))
    )
}

rule LINUX_Crontab_C2_Connection_200_98_8_82
{
  meta:
    description = "Detects crontab/persistence content connecting to known C2 IP"
    ioc_type = "ip + cron keywords"
    confidence = "medium"

  strings:
    $ip = "200.98.8.82"
    $cron1 = "crontab" nocase
    $cron2 = "/etc/cron" nocase
    $cron3 = "*/"  // common cron interval marker
    $bash  = "/bin/bash" nocase
    $sh    = "/bin/sh" nocase
    $curl  = "curl " nocase
    $wget  = "wget " nocase
    $nc    = "nc " nocase

  condition:
    $ip and (1 of ($cron*, $bash, $sh)) and (1 of ($curl, $wget, $nc) or $cron3)
}
