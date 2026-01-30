# Loan

## Loan01
> When digging deeper in the available evidence after the incident, we detected unusual web requests on the "loan" server. From which IP address did these requests originate?

> Flag: ``

## Loan02
> Which country does that IP address come from?

> Flag: ``

## Loan03
> Which organization does this IP address belong to?

> Flag: ``

## Loan04
> A scanning attack was performed on the loan server. Which application server (Java web server) is running on the loan host?

> Flag: ``

## Loan05
> After the requests indicating a scan, we recorded several requests suggesting that content was being stored on the server. How many such requests were created?
 
> Flag: ``

## Loan06
> What URL path does the first of these requests have?
 
> Flag: ``

## Loan07
> Right after PUT request, there is GET request, repeated three times. Seems like attemps to exploit some vulnerability. Based on already collected evidence, what could be the CVE of this vulnerability? (format CVE-XXXX-XXXXX)

> Flag: ``

## Loan08
> Nice, remote code execution... When was this vulnerability reported to the Tomcat security team? Format: `YYYY-MM-DD`.

> Flag: ``

## Loan09
> What is the name of the Apache Tomcat feature where the vulnerability exists? It is also unofficial name of this vulnerability used by security vendors.


> Flag: ``

## Loan10
> Partial PUT typically uses which header in an HTTP request to specify which part of the resource should be modified?

> Flag: ``

## Loan11
> Were those RCE attempts successful? I am sure you know the answer, even before digging in more logs. A few minutes after the last of those 3 requests, an alert in company SIEM related to the loan machine was triggered. What is the name of the alert?


> Flag: ``

## Loan12
> Between which two public IP addresses did the communication take place in the given alert? (format source,destination)

> Flag: ``

## Loan13
> Under what name was the first downloaded file saved to disk? Full path

> Flag: ``

## Loan14
> What User-Agent was used in the request related to the download of the file?

> Flag: ``

## Loan15
> What http server was used to host this file on attacker's side?

> Flag: ``

## Loan16
> Under which user account was the file executed?

> Flag: ``

## Loan17
> What is the PPID of the process that executed this file?

> Flag: ``

## Loan18
> What is the name of the process whose ID you provided in the previous question?

> Flag: ``

## Loan19
> The process which executed the file behaves suspiciously and we observed unusual communication. Which IP and port is the file communicating with? (format ip:port)

> Flag: ``

## Loan20
> What shebang is specified at the beginning of the aforementioned file?


> Flag: ``

## Loan21
> If you focus on the second line of the file, you will see that it is a reverse shell. What PID does the process have that represents the reverse shell itself?

> Flag: ``

## Loan22
> Which file was executed via the reverse shell (full path)?

> Flag: ``

## Loan23
> What is the alert ID of the alert related to this file?

> Flag: ``

## Loan24
> What is the IP address from which the file was downloaded?

> Flag: ``

## Loan25
> What is the country name related with this IP address?

> Flag: ``

## Loan26
> Which CVE does the file cpu_test.sh exploit? (format CVE-XXXX-XXXXX)

> Flag: ``

## Loan27
> Oh great, so immediately after execution of the exploit, we have attacker with root privileges. Attackers often leave easter eggs. What is the attacker’s nickname who successfully performed the privilege escalation?

> Flag: ``

## Loan28
> Right after gaining root privileges, attacker started doing system recon. Which process name was used to perform the search?

> Flag: ``

## Loan29
> Attacker tried to find files, which contain some specific string. What was that string?

> Flag: ``

## Loan30
> This is a (well) known string for access keys of which cloud provider?

> Flag: ``

## Loan31
> Into which file did the attacker write the results (full path)?

> Flag: ``

## Loan32
> From which URL did the attacker try to download rclone installation script?


> Flag: ``

## Loan33
> Where exactly did the attacker copy the file they were writing into?

> Flag: ``

## Loan34
> What was the server domain that file /tmp/hsperfdata_tomcat.tmp was uploaded to?

> Flag: ``

## Loan35
> There was another file copied to the destination. From the home directory of which user was the file copied?

> Flag: ``

## Loan36
> What is the name of the copied file?

> Flag: ``

## Loan37
> What is usually the content of the copied file? Answer accepts 2 and 3 word variant

> Flag: ``

## Loan37.5
> We were able to recover this OpenSSH private key [id_ed25519](img/Loan/id_ed25519). What is the passphrase?


> Flag: ``

## Loan38
> We can also see that something was downloaded to the host, what process.name was present in the download log?

In `auditbeat-*` search for `host.name :"loan"` and look at the logs around time `18:00` to `18:15`, after the `rcone` upload, there is another download via `wget`:

![](img/Loan/20260130134523.png)

> Flag: `wget`

## Loan39
> What is the full download URL?

> Flag: ``

## Loan40
> So, ligolo-ng was downloaded. Great pivoting and tunneling tool used by many pentesters, agent does not even require full administrator privileges, but it works differently than many other similar tools. It does not initiate SOCKS proxy. What kind of interface does it use instead? 2 words

> Flag: ``

