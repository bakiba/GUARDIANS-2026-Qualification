rule HUNT_AWS_AccessKeys_And_Attacker_Context
{
  meta:
    description = "Detects presence of specific AWS access keys and related incident context strings"
    ioc_type = "aws_access_key + account + ip"
    confidence = "medium"
    note = "Best for log/text scanning; do not run alone as malware conviction"

  strings:
    // Specific keys from IOC list
    $k1 = "AKIATECIQI6O6U5P3WUZ"
    $k2 = "AKIATECIQI6O6Y3CBDOH"

    // Accounts / actors
    $acct1 = "aws-testing" nocase
    $acct2 = "loan-apiuser" nocase

    // IP tied to AWS stolen key usage
    $ip1 = "138.199.21.200"

    // SSH key fingerprint format (as seen in IOC)
    $sshfp = "b4:f4:2a:90:b8:f8:fd:e4:0f:32:66:4a:bd:0c:00:63:ae:31:8b:bb" nocase

  condition:
    any of ($k*) or
    (1 of ($acct*) and $ip1) or
    ($acct1 and $sshfp)
}

rule HUNT_O365_Compromise_DavidJalovec_AnonymizedIP
{
  meta:
    description = "O365/Entra compromise pivot: known attacker IP + eMClient UA"
    ioc_type = "ip + useragent"
    confidence = "medium"

  strings:
    $ip = "84.252.113.67"
    $ua = "eMClient/10.4.4209.0" nocase

    // Optional nearby context keywords
    $o365a = "User Risk Detection" nocase
    $o365b = "azure.identity_protection" nocase
    $o365c = "anonymizedIPAddress" nocase

  condition:
    $ip and ($ua or 1 of ($o365*))
}

rule HUNT_Malicious_Extension_Download_Infrastructure
{
  meta:
    description = "Pivot for extension.zip and observed download source IP"
    ioc_type = "filename + ip"
    confidence = "low_to_medium"

  strings:
    $f1 = "extension.zip" nocase
    $ip = "54.175.155.238"

  condition:
    $f1 and $ip
}

rule HUNT_Tomcat_RCE_CVE_2025_24813_Related_IOCs
{
  meta:
    description = "Pivot for Tomcat RCE exploitation IP and follow-on artifacts"
    ioc_type = "ip + filenames + server banner"
    confidence = "medium"
    note = "Good for web logs, bash history, curl/wget traces, reverse shell staging"

  strings:
    $ip_exploit = "176.9.15.89"

    $f1 = "memory_test.sh" nocase
    $f2 = "cpu_test.sh" nocase

    $ip_shell = "192.30.253.137"
    $srv = "SimpleHTTP/0.6 Python/3.13.11" nocase

    // Ligolo-ng agent URL (as given)
    $ligolo = "github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_linux_amd64.tar.gz" nocase

  condition:
    $ip_exploit and (1 of ($f*) or $srv or $ligolo or $ip_shell)
}
