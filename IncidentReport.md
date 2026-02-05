# Coolbank Incident Report

## Executive Summary

## Incident timeline

  - `2026-01-12T01:03:45.000Z` - [HR] Initial infection of Lea's personal computer G2026/Windows 11, from where Vidal Stealer stole 17 unique password and persistent cookie ESTSAUTHPERSISTENT that could be used to attacker to access Lea's O365 account.
  - `2026-01-15T16:51:03.000Z` - [AWS] attacker logged to AWS from IP 138.199.21.200 using stolen accesskey AKIATECIQI6O6Y3CBDOH for loan-apiuser.
  - `2026-01-15T16:52:18.000Z` - [AWS] attacker created AWS user aws-testing with access key AKIATECIQI6O6U5P3WUZ and attached access policy arn:aws:iam::aws:policy/AdministratorAccess.
  - `2026-01-15T16:56:44.000Z` - [AWS] attacker listed objects in `loan-applicants` S3 bucket.
  - `2026-01-15T16:58:14.000Z` - [AWS] attacker downloaded 7 objects from `loan-applicants` S3 bucket (see [list of exfiltrated documets](#sensitive-documents-exfiltrated)).
  - `2026-01-15T17:00:29.000Z` - [AWS] loan-apiuser created ssh key pair (testing_web_key/b4:f4:2a:90:b8:f8:fd:e4:0f:32:66:4a:bd:0c:00:63:ae:31:8b:bb).
  - `2026-01-15T17:02:02.000Z` - [AWS] loan-apiuser started EC2 instance i-06f9c69d1c1cb1ece with public IP 16.170.218.1.
  - `2026-01-15T17:12:55.542Z` - [AWS] CryptoCurrency:EC2/BitcoinTool.B - The EC2 instance i-06f9c69d1c1cb1ece is communicating outbound with a known Bitcoin-related IP address 141.95.72.61.
  
  - `2026-01-15T20:13:13.971Z` - [HR] event with source 36.50.238.15 by lea.ciger@coolbank.eu created high alert Entra ID Protection - Risk Detection - Sign-in Risk. Lea logged in to Outlook Web from IP address located in 36.50.238.15/Singapore, owned by VPN provider while usually she logs in from 37.58.4.198. Further investigation showed that she logged from Chrome, while she usually used Edge and logged from IP. Her account was using single factor for authentication.
 
  - `2026-01-15T20:23:44.000Z` - [HR] attacker tried to access Azure Portal but it failed due to requirement to enroll for second factor authentication.
  - `2026-01-15T20:31:18.204Z` - [HR] attacker granted consent to 3rd party client (eM Client) to access Lea's account.
  - `2026-01-15T21:18:33.000Z` - [AWS] An administrator terminated the suspicious EC2 instance i-06f9c69d1c1cb1ece.
  - `2026-01-15T22:12:56.965Z` - [EXT] attacker installs NodeJS server on officewin5/192.168.12.8 that listens on port `3000` and collects keylogger data.
  - `2026-01-15T22:25:58.300Z` - [EXT] user `david.jalovec` downloads malicious browser extension `extension.zip` that is masked keylogger.
  - `2026-01-15T22:40:11.346Z` - [EXT] O365 credentials of `david.jalovec` were stolen by keylogger.
  - `2026-01-15T23:38:14.578Z` - [EXT] attacker used stolen O365 credentials from `david.jalovec` to login to One Outlook Web using eM Client.
  - `2026-01-15T23:52:48.000Z` - [EXT] attacker created inbox rule in Outlook to forward incoming emails to `miloslav.dubnicka@coolbank.eu` and another rule to move email with subject containing `invoice` to Archive folder.
  - `2026-01-16T00:40:12.00Z`  - [EXT] attacker sent fake email with subject `faktura` to `david.jalovec@coolbank.eu` with intention to trick David paying fake invoice.
  



## Impact Analysis

### Credentials compromised
  - AKIATECIQI6O6U5P3WUZ - loan-apiuser AWS access key.
  - Lea Ciger (lea.ciger@coolbank.eu) - compromised O365 credentials.
  - David Jalovec (david.jalovec@coolbank.eu) - stolen O365 credentials via keylogger.
  - Miloslav Dubnicka (miloslav.dubnicka@coolbank.eu) - 

### Sensitive documents exfiltrated

  - applications/106db801-b157-4e17-a04e-c9b92a54ad04.json [407b]
  - applications/6b6ee0a3-5f54-4a65-bef9-2858e7c89a44.json [433b]
  - applications/43402e88-148b-4221-92a3-cd9e8c239a9a.json [423b]
  - applications/cdc208d6-d601-4b75-8364-b5173b5e8e6a.json [420b]
  - applications/6028eeec-d4d2-4002-9c04-63c252137e58.json [427b]
  - applications/1ef41cd1-d150-45fc-bf3d-fc41abd0c22b.json [430b]
  - applications/2648684d-7288-47bc-96fd-6d1348860cb3.json [435b]

### Hosts impacted
- List of hosts compromised:
  - officewin5/192.168.12.8
  - loan/192.168.11.49

- List of hosts impacted by ransomware:

## Lessons learned

- **Gap Analysis**: 
- **Recommendations for Improvement**: 

## Indicators of Compromise (IoCs)

|IOC type | IOC value | Comments |
|---------| --------- | -------- |
| Malware | C:\Users\leuska\AppData\Local\Temp\11808150101\bDjqu09.exe | Vidar Sealer |
| IP      | 138.199.21.200  | attacker loged to AWS using stolen loan-apiuser accesskey |
| User    | aws-testing     | attacker created AWS user |
| AWS KEY | AKIATECIQI6O6U5P3WUZ | AWS access key for aws-testing user |
| AWS KEY | AKIATECIQI6O6U5P3WUZ | compromized AWS access key used by legitimate loan-apiuser |
| SHA1    | 0b7fc40a15b5f471261dd76a16c6acd20e055373 | sha1 hash of the malicious browser extension |
| File    | extension.zip | name of the file containing malicious browser extension |
| IP      | 54.175.155.238  | IP address from which malicious browser extension was downloaded |
| IP      | 84.252.113.67   | attacker logged to O365 using stolen credentials from David Jalovec |
| UserAgent| eMClient/10.4.4209.0 | UserAgent used by attacker duing logon |
| IP     | 176.9.15.89      | IP address from which the tomcat11 RCE (CVE-2025-24813) was exploited |

## Asset list
- officewin1/192.168.12.4/david.jalovec
- officewin3/192.168.12.6/zdenka.jakubcek
- officewin5/192.168.12.8/miloslav.dubnicka
- loan/192.168.11.49