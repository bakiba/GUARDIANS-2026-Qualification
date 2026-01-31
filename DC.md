# DC

## DC01
> In Kibana, under Alerts, we observed multiple alerts from the host adc2ofc. What is the name of the last alert received within the Guardians time window on the adc2ofc?

Looking at the Kiana Security->Alerts dashboard and filter for hostname `adc2ofc`, we see the last alert received:

![](img/DC/20260131174952.png)

> Flag: `Multiple Alerts in Different ATT&CK Tactics on a Single Host`

## DC02
> For that alert, if we select Investigate in timeline within the correct time window, multiple alerts appear. What is the name of the last of these alerts?

 When clicking investigate in the timeline, no alerts were shown because timeframe was somehow messed-up... when selecting `Guardians` timeframe, the alerts were shown.

 ![](img/DC/20260131175146.png)

> Flag: `Process Execution from an Unusual Directory`

## DC03
> What was the process name detected by this alert?

Visible in previous task.

> Flag: `teafortwo.exe`

## DC04
> What is the full path to the executable file of this process?

By toggling the dialog window with details for the selected document, we can search for `process.command_line` field that will give us answer:

![](img/DC/20260131175542.png)

> Flag: `C:\Users\Public\Documents\teafortwo.exe`

## DC05
> What is the MD5 hash of this .exe file?

For this we need to switch to Discover dashbaord and open `winlogbeat-*` Data view and search for `teafortwo.exe` and look at the `file.hash.md5` field:

![](img/DC/20260131175844.png)

> Flag: `ae454079c93a7a1ce276756b9d62d196`

## DC06
> By analyzing this file in more detail, we discover it is malware. What type of malware is it?

For this type of information we turn to [VirusTotal](https://www.virustotal.com/) where we can enter the `md5` hash from previous task to search for information on mentioned malware. VirusTotal identified this sample as `ransomware.akira/filecryptor`

![](img/DC/20260131180205.png)

> Flag: `ransomware`

## DC07
> Which ransomware family does this sample belong to?

Visible in previous task.

> Flag: `akira`

## DC08
> When was the file first submitted to VirusTotal? Format: `YYYY-MM-DD HH:MM:SS UTC`.

Clicking on the `Detils` tab on VirusTotal page, we see History details:

![](img/DC/20260131180357.png)

> Flag: `2025-08-26 09:05:20 UTC`

## DC09
> Ransomware typically creates a ransom note. What is the filename of the ransom note in our case?

Search for `teafortwo.exe` in the `winlogbeat-*` Data view, display the `file.path` field and look at the `File created...` messages:

![](img/DC/20260131180832.png)

> Flag: `akira_readme.txt`

## DC10
> Under which user account was the ransomware executed?

Visible in previous task.

> Flag: `administratr`

## DC11
> What was the originating process for the ransomware file creation event?

From the previous search, we look at the oldest event and see that `AnyDesk.exe` created the `teafortwo.exe`:

![](img/DC/20260131181618.png)

> Flag: `AnyDesk.exe`

## DC12
> What other file (filename) was created by the same process?

Search for `process.name: "AnyDesk.exe"`, apply filter for `event.action:File created (rule: FileCreate)` and look at the created files:

![](img/DC/20260131182009.png)

> Flag: `backupTool.exe`

## DC13
> What is the sha256 hash of that file?

Search for `backupTool.exe` and add the `file.hash.sha256` field to the table view:

![](img/DC/20260131182342.png)

> Flag: `c9a38fa7b619a1bc814fcf381a940245dfa8d24ae51e7ec22f9461eae288ede3`

## DC14
> What is the file path where that file was saved?

Visible in previous task.

> Flag: `C:\Users\Public\Downloads\backupTool.exe`

## DC15
> After the file was created, it initiated a network connection. What was the destination IP address and port? (Format: IP:PORT)

Same search as previous, just add `desination.ip` and `destination.port` fields to the table view:

![](img/DC/20260131182754.png)

> Flag: `176.9.13.248:443`

## DC16
> An alert was also associated with this file. What is the name of the framework that was used?

In the Kibana Security->Alerts dashboard, we can search for the destination IP `176.9.13.248` and we'll find single alert related to this. Note that searching for alerts on `ADC2ofc` will not help finding the answer as the alert is associated with the perimeter firewall `WGM-SK-FW002`.

![](img/DC/20260131183033.png)

> Flag: `havoc`

## DC17
> Havoc is a C2 framework, as shown in the alert. Who is the primary author of this post-exploitation command-and-control framework?

> Flag: ``

## DC18
> The attacker established persistence using the Havoc framework. However, before the ransomware and persistence activity, we observed the creation of a new user account in the logs. What is the name of the newly created user?

> Flag: ``

## DC19
> What password did the attacker set for that user?

> Flag: ``

## DC20
> We then observed that the user was added to a group. What is the group name?

> Flag: ``

## DC21
> Which built-in Windows utility is used to manage Volume Shadow Copies (VSS)?

> Flag: ``

## DC22
> Review the alerts. Which MITRE ATT&CK technique ID is detected in the alerts related to this tool on adc2ofc?

> Flag: ``

## DC23
> What is the name of this MITRE ATT&CK technique?

> Flag: ``

## DC24
> Since the shadow copies were deleted, which command did the attacker use to list shadow copies?

> Flag: ``

## DC25
> Which drive was targeted when creating the shadow copy?

> Flag: ``

## DC26
> Question was removed.


## DC27
> Which two sensitive files were created in the unusual temporary directory? (Format: file1,file2)

> Flag: ``

## DC28
> Let’s recap: the attacker created a disk snapshot using Volume Shadow Copies, exposed it locally via a filesystem link, and extracted important system files into a temporary folder. Under which user account was this activity performed?

> Flag: ``

## DC29
> Still the same user?! On which host was this user account created?

> Flag: ``

## DC30
> In the logs, we see the cmd command used to create the user. What is the parent process of that specific cmd.exe instance?

> Flag: ``

## DC31
> Which OutFile value was used in the Invoke-WebRequest command on host adc2ofc, under the parent process Velociraptor.exe ?

> Flag: ``
