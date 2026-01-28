# AWS

## AWS01
> GuardDuty detected cryptocurrency mining activity. What is the name of the first rule that identified this activity?

In the Security->Alerts dashboard we did not find any alert related to cryptocurrency mining activity. We then went to Discover dashboard, opened `aws-*` Data view and search for `*mining*`. Add field `rule.name` to the table:

![](img/AWS/20260128094927.png)

> Flag: `CryptoCurrency:EC2/BitcoinTool.B`

## AWS02
> What is the EC2 instance ID that was flagged for potential cryptocurrency mining activity?

> Flag: ``

## AWS03
> CloudWatch detected abnormal CPU utilization on the compromised instance. What was the highest value of CPU average percentage recorded? (Number only, no symbols)

> Flag: ``

## AWS04
> What was the first root domain identified by GuardDuty findings that indicated crypto mining alert?

> Flag: ``

## AWS05
> Seems like some funny internet magic money. What is the name of cryptomining application? (all lowercase)

> Flag: ``

## AWS06
> What is the full file path of the cryptominer executable detected by GuardDuty EBS scanning?

> Flag: ``

## AWS07
> GuardDuty detected a script used to optimize the system for mining. What is the name of the script that enables huge memory pages?

> Flag: ``

## AWS08
> An administrator terminated the suspicious EC2 instance. What is the arn of the admin who performed this action?

> Flag: ``

## AWS09
> At what time was this suspicious EC2 instance stopped by the administrator? (Format hh:mm:ss)

> Flag: ``

## AWS10
> What source country did the administrator logged in from when stopping the malicious instance?

> Flag: ``

## AWS11
> That instance did not ring a bell. What region it was running in?

> Flag: ``

## AWS12
> Weird. No running instances should be in that region. What user did set it up? (Give his full identity arn)

> Flag: ``

## AWS13
> That is our legit loan application account, but used only for uploading forms from on-prem server. What EC2 instance type did the account choose for their cryptomining operation?

> Flag: ``

## AWS14
> What AMI ID was used for this instance?

> Flag: ``

## AWS15
> What is assigned public IP address of newly created EC2 instance?

> Flag: ``

## AWS16
> What security group ID was associated with the attacker's EC2 instance at launch?

> Flag: ``

## AWS17
> Before launching the instance, the attacker created a key pair for SSH access and attached to EC2. What is the name of the key pair created?

> Flag: ``

## AWS18
> What is the fingerprint of the SSH key pair created by the attacker?

> Flag: ``

## AWS19
> What IP address came these suspicious activities from?

> Flag: ``

## AWS20
> What city is this IP originating from?

> Flag: ``

## AWS21
> After logging in with the stolen credentials, the attacker might enumerated account permissions. Which IAM API call indicates the attacker was checking their identity? (event.action)

> Flag: ``

## AWS22
> Based on the user agent string in CloudTrail, what Linux distribution was the attacker using when executing AWS CLI commands? (lowercase without version)

> Flag: ``

## AWS23
> What is the access key ID that was used by the attacker for unauthorized access?

> Flag: ``

## AWS24
> Except creating the VM, keys and policies did the attacker created other backup access way? If yes, what is event.action of it. If no, type "no"

> Flag: ``

## AWS25
> What is user name of this new bad boy?

> Flag: ``

## AWS26
> The attacker accessed sensitive company data in S3 objects. What is the name of the S3 bucket that was accessed?

> Flag: ``

## AWS27
> How many files did the attacker download from S3?

> Flag: ``

## AWS28
> What was name of the biggest S3 object the attacker downloaded? Access key of object based on S3 access logs.

> Flag: ``

## AWS29
> What is the total size (in bytes) of all objects downloaded by the attacker?

> Flag: ``

## AWS30
> What HTTP status code was returned for the attacker's S3 GetObject requests, confirming successful downloads?

> Flag: ``

## AWS31
> What is the legitimate public IP from which loan user usually connects?

> Flag: ``

## AWS32
> What is the most common operation that legitimate loan user do?

> Flag: ``

## AWS33
> Which Host fqdn is accessed when uploading data?

> Flag: ``

## AWS34
> Which region is this object located in?

> Flag: ``

## AWS35
> Based on official Amazon IP address range for this region and S3 service, what IP range is used, with mask /22? (Answer X.X.X.X/XX)

> Flag: ``

## AWS36
> What is the internal private IP in coolbank infrastructure that accesses this public range specifically around time loan-applicants bucket is updated?

> Flag: ``

## AWS37
> What is the hostname of the device with this IP?

> Flag: ``