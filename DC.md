# DC

## DC01
> In Kibana, under Alerts, we observed multiple alerts from the host adc2ofc. What is the name of the last alert received within the Guardians time window on the adc2ofc?

> Flag: ``

## DC02
> For that alert, if we select Investigate in timeline within the correct time window, multiple alerts appear. What is the name of the last of these alerts?

> Flag: ``

## DC03
> What was the process name detected by this alert?

> Flag: ``

## DC04
> What is the full path to the executable file of this process?

> Flag: ``

## DC05
> What is the MD5 hash of this .exe file?

> Flag: ``

## DC06
> By analyzing this file in more detail, we discover it is malware. What type of malware is it?

> Flag: ``

## DC07
> Which ransomware family does this sample belong to?

> Flag: ``

## DC08
> When was the file first submitted to VirusTotal? Format: `YYYY-MM-DD HH:MM:SS UTC`.

> Flag: ``

## DC09
> Ransomware typically creates a ransom note. What is the filename of the ransom note in our case?

> Flag: ``

## DC10
> Under which user account was the ransomware executed?

> Flag: ``

## DC11
> What was the originating process for the ransomware file creation event?

> Flag: ``

## DC12
> What other file (filename) was created by the same process?

> Flag: ``

## DC13
> What is the sha256 hash of that file?

> Flag: ``

## DC14
> What is the file path where that file was saved?

> Flag: ``

## DC15
> After the file was created, it initiated a network connection. What was the destination IP address and port? (Format: IP:PORT)

> Flag: ``

## DC16
> An alert was also associated with this file. What is the name of the framework that was used?

> Flag: ``

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
