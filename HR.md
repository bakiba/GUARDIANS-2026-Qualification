# HR

## HR01
> Shortly after 21:00 CET, several alerts about risky sign-in were generated in the company SIEM. What is the username involved in these alerts? Format: user.name@domain.tld

We begin by opening Kibana interface and navigate to Security->Alerts dashboard, where we look at alerts generated around 21:00 and notice two of them where user `lea.ciger@coolbank.eu` was mentioned.

![](img/HR/20260128091819.png)

> Flag: `lea.ciger@coolbank.eu`

## HR02
> Let's focus on the alert with name "Entra ID Protection - Risk Detection - Sign-in Risk". What is the severity of the alert?

From previous task we can see that severity of the alert is `high`.

> Flag: `high`

## HR03
> What is the IP address from which Lea Ciger logged in?

Also from task [HR01](#hr01) from the alert details we see `event with source 36.50.238.15`.

> Flag: `36.50.238.15`

## HR04
> What is the name of the country Lea logged in from? (There are different countries in different databases, check also based on ASN info)

Checking the IP against [AbuseIPDB](https://www.abuseipdb.com/check/36.50.238.15), we see it is `Singapore`.

![](img/HR/20260128092625.png)

> Flag: `Singapore`

## HR05
> What is the ASN organization name? Format: Two words

> Flag: ``

## HR06
> Now check the exact reason why the detection rule fired. What is the risk type detected?

> Flag: ``

## HR07
> What is the display name of the application Lea logged in to?

> Flag: ``

## HR08
> Quick recap - Lea logged in to Outlook Web from IP address located in Bangladesh, owned by VPN provider. Could be really suspicious or just forgotten VPN. Let's find out more. Quickest way to find out would be to call her. Unfortunately, she is not picking up her phone. We need to find out ourselves. What is the user_agent.name used for this login?

> Flag: ``

## HR09
> What is the user_agent.name in Lea's other historical logs?

> Flag: ``

## HR10
> Hmm, first inconsistency. But it still could be benign. Based on the user's historical login patterns, which IP address represents Lea’s primary home/office location?

> Flag: ``

## HR11
> What was the authentication requirement of the login from Bangladesh?

> Flag: ``

## HR12
> What was the authentication method of the login from Bangladesh?

> Flag: ``

## HR13
> What was the authentication step result?

> Flag: ``

## HR14
> After correct password, authentication sequence is (usually) interrupted and user is presented with "Stay signed in?" prompt. How is this process or feature called by Microsoft?

> Flag: ``

## HR15
> You can see in the logs if the user was presented the Keep me signed in prompt thanks to one specific error/status code. What code is it?

> Flag: ``

## HR16
> If the user clicks No, transient cookie is created. What is the name of the cookie?


> Flag: ``

## HR17
> If the user closes the browser, the ESTSAUTH cookie is destroyed, requiring a fresh login next time. By default, an ESTSAUTH cookie has a validity of up to how many hours?

> Flag: ``

## HR18
> If the user decides to clicks Yes, persistent cookie is created. What is the name of the cookie?

> Flag: ``

## HR19
> Keep this info in mind, you will need it bit later. Let's get back to the incident. After login, Lea or attacker checked Outlook web and read some emails. Based on emails available in the Inbox folder, who was trying to reach Lea in Microsoft Teams?

> Flag: ``

## HR20
> What is the Internet Message ID of the email with subject "Doplnenie k dohode"? Format: without <> brackets.

> Flag: ``

## HR21
> You probably noticed that you need to jump between o365 and azure logs if you want to see the complete picture what happened. Some event are shown different in both of them, some are even missing. It is also the case here. There was an attempt to access other web application few minutes later, but was not successful. What is the error / status code of this attempt?

> Flag: ``

## HR22
> Based on Microsoft error codes reference, what is the logon error name (or description)? Format: VeryLongWordAlmostGermanStyle

> Flag: ``

## HR23
> As you probably read yourself, it means that user needs to enroll for second factor authentication to access this application. Seems that our user was lazy to do this, as logs don't show any successful login. What was the web application with request to enroll 2fa?

> Flag: ``

## HR24
> If except o365 and azure logs you also are looking to SIEM alerts section, you could notice several alerts for events related to Lea Ciger. Consent was granted to third party application to access Lea's account. What is the name of the application?

> Flag: ``

## HR25
> What is the full name of the OS on which eM Client is running?

> Flag: ``

## HR26
> What is the first country from which eM Client connected to Lea's account?

> Flag: ``

## HR27
> There was also some other activity, accessing Lea's emails from other countries, apparently through VPN. How did attacker get Lea's password to O365? Admin together with Lea reviewed mail trace logs for signs of phishing email, browser history too, but they haven't found anything. Lea's computer and inbox were clean. They reached to Binary Confidence for help and soon found out. And you can see yourself too :)

> Binary Confidence is proud partner of Hudson rock with access to the Industry's Most Robust Compromised Credentials Data Source - Cavalier. Just visit their webpage and find out yourself.

> How many compromised Coolbank employees did you find?

> Flag: ``

## HR28
> There is some more info available using Hudson rock free tools, but we will show you what is inside. Check the attached archive with screenshots from the paid platform and original stealer log. What is the name of the stealer log with Lea's credentials?
> [1._domain_search.jpeg](img/HR/01._domain_search.jpeg) [02._stealer.jpeg](img/HR/02._stealer.jpeg) [03._AI_analyzer.jpeg](img/HR/03._AI_analyzer.jpeg) [hudsonrock.zip](img/HR/hudsonrock.zip)

> Flag: ``

## HR29
> What was the Date and Time of the initial infection according to the log metadata? Format: `YYYY-MM-DD HH:mm`.

> Flag: ``

## HR30
> What is the exact path from which the malware was executed on the victim's PC?

> Flag: ``

## HR31
> Which Stealer Family generated this log?

> Flag: ``

## HR32
> The stealer captured Lea’s IP address at the time of infection. What was it?

> Flag: ``

## HR33
> What Antivirus software was installed on the infected computer?

> Flag: ``

## HR34
> According to the stealer log, what is the Computer Name of Lea Ciger’s infected machine?

> Flag: ``

## HR35
> What was the install date of the machine?

> Flag: ``

## HR36
> How many unique passwords are in the stealer log?

> Flag: ``

## HR37
> What is the value of the stolen cookie which could be used by attacker to access Lea's O365 account even without password or with 2fa enabled?

> Flag: ``

## HR38
> This is the last question of this category. What phone number is visible on the last entry in the leaked browser history?

> Flag: ``