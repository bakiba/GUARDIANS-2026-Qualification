# DMZ

## DMZ01
> After a successful ligolo-ng agent installation. The attacker wanted to broaden their attack surface to other hosts in the dmz subnet which command did the attacker use to see the host IP?

> Flag: `ip a`

## DMZ02
> Let's now look back into the Alerts section, which alert may signalize a network discovery attempt?

> Flag: `Possible internal Port Scan detected`

## DMZ03
> Attacker discovered many hosts across the dmz subnet, did he successfully access any of the hosts? If yes submit the hostname of first accessed host.

> Flag: `dmzFTP`

## DMZ04
> As which user did attacker log in to the dmzFTP host?

> Flag: `spravca`

## DMZ05
> What is the name of a binary log file that records all login and logout activities, system startups, and shutdowns. This file is not a plain text log; it is typically parsed by tools like the last command to display session history. Full path.

> Flag: `/var/log/wtmp`

## DMZ06
> Back to dmzFTP. What was the command used by attacker for initial host OS identification. Whole terminal entry.

> Flag: `cat /etc/os-release`

## DMZ07
> Right after the initial OS enumeration. We can see a command that initiated a download of a file. What software was downloaded?

> Flag: `teamviewer`

## DMZ08
> What was the source URL of TeamViewer download?

> Flag: `https://download.teamviewer.com/download/linux/teamviewer_amd64.deb`

## DMZ09
> After a successful TeamViewer installation, the software was started with a password, what was it?

> Flag: `hackedftp753`

## DMZ10
> Shortly before the TeamViewer execution, a user was created. What was the name of the user?

> Flag: `admfile`

## DMZ11
> What was the password of this user?

> Flag: `heslo200`

## DMZ12
> Attacker later tried to establish a persistence on the dmzFTP host, which command was used? 1 word.

> Flag: `crontab`

## DMZ13
> After the cron task creation, we can see some network activity coming from the host. Go back to the alerts section and check if there were any periodicly generated alerts. What was the name of the alert, that this host generated?

> Flag: `Shell Script`

## DMZ14
> Now let's switch back to just open alerts, what was the name of the first downloaded file from a foreign IP.

> Flag: `healthcheck`

## DMZ15
> Which user agent was used during the download?

> Flag: `curl/7.58.0`

## DMZ16
> Before the successful download, we recorded several failures. What is the error code explanation for those attempts?

> Flag: `404 - Nothing matches the given URI.`

## DMZ17
> What was the foreign IP, from which the file originated?

> Flag: `200.98.8.82`

## DMZ18
> Now it's time to check 3rd party tools like abuseipdb for IP reputation. What was the country of origin?

> Flag: `Brazil`

## DMZ19
> What was the full ISP name listed in AbuseIPDB?

> Flag: `Universo Online S.A.`

## DMZ20
> What was the second file name in the alerts section?

> Flag: `file`

## DMZ21
> Focus on the file. Which directories are deleted after a successful exfiltration? Sort them alphabetically. Format: /dir1,/dir2,/dir3

> Flag: `/home,/root,/var/www`

## DMZ22
> To which URL did the file exfiltration take place?

> Flag: `http://200.98.8.82:4443/upload`

## DMZ23
> Which user started these curl requests that downloaded the files?

> Flag: `root`

## DMZ24
> Based on the cron activity regarding the healthcheck file. We can see that it was executed regularly and quite often, what was the minute field value in the crontab while creating the cron job based on the repetition of the activity?

> Flag: `*/5`

## DMZ25
> What was the second host that attacker successfully logged in to from loan?

> Flag: `velociraptor`

## DMZ26
> What was the time of the login to the second host? Use ISO8601 format e.g.: 2026-01-17T22:49:53

> Flag: `2026-01-15T19:54:38`

## DMZ27
> After gaining initial access, adversaries often propagate through the environment to explore and compromise additional systems. What is this tactic called?

> Flag: `lateral movement`

## DMZ28
> What is the MITRE ATT&CK Tactic ID of Lateral Movement?

> Flag: `TA0008`

## DMZ29
> After attacker successfully logged into velociraptor host. Using velociraptor GUI he created a user that was later added to a highly privileged group. What was the full commandline of user creation?

> Flag: `net user administratr B3ckup42 /ADD /DOMAIN`

## DMZ30
> What is the highly privileged group that the newly created user was added to?

> Flag: `Domain Admins`

## DMZ31
> Something was later downloaded through velociraptor, what is the full web request path of the downloaded file?

> Flag: `https://download.anydesk.com/AnyDesk.exe`

## DMZ32
> To which folder was the downloaded file saved? Full path.

> Flag: `C:\Users\Public\`

## DMZ33
> We can later see that there was a specific argument supplied to the installation command that launches the software automatically as Windows boots up, what was the argument? Accepted answer format is `--argument`.

> Flag: `--start-with-win`

## DMZ34
> Right after the software installation, the attacker set a backdoor password to the program. What was the password?

> Flag: `IwAsHere42`

## DMZ35
> This process of creating a backdoor for easy access has a specific MITRE ATT&CK Technique name, what is it?

> Flag: `Remote Access Tools`

## DMZ36
> There is a specific MITRE ATT&CK subtechnique that mentions that attackers use legitimate RMM tools such as AnyDesk, what is the ID?

(This is the last question of Guardians 2026 qualification. Congratulations!)

> Flag: `T1219.002`