# EXT

## EXT01
> Analysts in your organization noticed another user's suspicious logon from foreign country. After initial analysis you realize that the leak may be much worse then it seems. While analyzing emails you notice conversation about new browser extension that users started installing. What is email of the user who notified colleagues of new extension?

> Flag: ``

## EXT02
> You take a closer look at the emails and write down some things you have noticed as they might be important down the road. What is the subject of email chain in which employees discuss this extension?

> Flag: ``

## EXT03
> When was the first email regarding extension sent? 
Use ISO8601 format e.g.: 2026-01-17T22:49:53

> Flag: ``

## EXT04
> What are the emails of users that replied in conversation with Miroslav Jakabovic about extension?
Sort answers in alphabetical order by name and separate values by comma

> Flag: ``

## EXT05
> Several users visited web mentioned in the email and downloaded the extension. Your thoughts lead you to network traffic and file streams. What is IP of the server that extension was downloaded from?

> Flag: ``

## EXT06
> What is the file extension of the file that was downloaded from the server?

> Flag: ``

## EXT07
> What are IPs of devices that downloaded extension from this server?
Sort IP addresses in ascending order and separate values by comma

> Flag: ``

## EXT08
> You have noticed multiple workstations that download the extension. What are the names of the computers that downloaded the extension?
Sort hostnames in alphabetical order and separate values by comma

> Flag: ``

## EXT09
> Which user downloaded extension as first?

> Flag: ``

## EXT10
> Which user downloaded extension as second?

> Flag: ``

## EXT11
> Which user downloaded extension as third?

> Flag: ``

## EXT12
> Closer look at the downloaded files reveals that they are not the same. What is the sha1 hash of the extension file downloaded as first?

> Flag: ``

## EXT13
> What is the sha1 hash of the different extension file?

> Flag: ``

## EXT14
> This is very interesting, two different versions of the same extension downloaded within 30 minutes. Let's check the difference. The second one seems to have some nasty functionality and based on the actual code, wants to communicate with some IP addresses. What is the IP address in the source code of the updated extension?

> Flag: ``

## EXT15
> Internal IP address? This doesn't make sense. What is the hostname of the machine with this IP address?

> Flag: ``

## EXT16
> Which user does this workstation belong to?

> Flag: ``

## EXT17
> Which workstation were credentials extracted from?

> Flag: ``

## EXT18
> Which windows process was used to install and launch JS runtime environment later utilized during data collection?

> Flag: ``

## EXT19
> Which JS runtime environment did user utilize to launch server and collect data from other workstations?

> Flag: ``

## EXT20
> What is the full directory path where the suspicious extension's data collection file is located?

> Flag: ``

## EXT21
> What is the PID of the process that executed server file for the first time

> Flag: ``

## EXT22
> Which package manager was used to install dependencies

> Flag: ``

## EXT23
> Your colleagues analyzed workstation and discovered file that seems to store stole data. Can you identify whose email password was stolen?
> [keylogger.txt](img/EXT/keylogger.txt)

> Flag: ``

## EXT24
> What is the password for the account?

> Flag: ``

## EXT25
> When was the password submitted? Expected answer is timestamp.

> Flag: ``

## EXT26
> Once you found out origin of the leak you decided to take a closer look at the foreign login. From which foreign IP did attacker log in?

> Flag: ``

## EXT27
> From which country did the login come from?

> Flag: ``

## EXT28
> Which organization owns server that login came from?

> Flag: ``

## EXT29
> What app did attacker use to log into the accout?

> Flag: ``

## EXT30
> What user agent was used by attacker during logon?

> Flag: ``

## EXT31
> As you slowly uncover plot of the attack you take a look at activities of the attacker. How many unique rules were created by the attacker?

> Flag: ``

## EXT32
> When was the forward rule created? Use ISO8601 format e.g.: `2026-01-17T22:49:53`.

> Flag: ``

## EXT33
> What email account were the incoming emails forwarded to?

> Flag: ``

## EXT34
> What keyword is required in subject to execute second rule?

> Flag: ``

## EXT35
> To which folder is email moved to when rule is executed?

> Flag: ``

## EXT36
> When was the email that was moved to archive accessed by the attacker? Use ISO8601 format e.g.: `2026-01-17T22:49:53`.

> Flag: ``

## EXT37
> What subject did the attacker use to bypass this rule and send fake email with similar subject?

> Flag: ``