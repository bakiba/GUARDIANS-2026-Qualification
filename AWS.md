# AWS

## AWS01
> GuardDuty detected cryptocurrency mining activity. What is the name of the first rule that identified this activity?

In the Security->Alerts dashboard we did not find any alert related to cryptocurrency mining activity. We then went to Discover dashboard, opened `aws-*` Data view and search for `*mining*`. Add field `rule.name` to the table:

![](img/AWS/20260128094927.png)

> Flag: `CryptoCurrency:EC2/BitcoinTool.B`

## AWS02
> What is the EC2 instance ID that was flagged for potential cryptocurrency mining activity?

In the same log we can find information in the message field:
```
"message": [ "The EC2 instance i-06f9c69d1c1cb1ece is communicating outbound with a known Bitcoin-related IP address 141.95.72.61." ],
```
> Flag: `i-06f9c69d1c1cb1ece`

## AWS03
> CloudWatch detected abnormal CPU utilization on the compromised instance. What was the highest value of CPU average percentage recorded? (Number only, no symbols)

For this we switch Data view to `metrics-*` set the filter on `cloud.instance.id : i-06f9c69d1c1cb1ece` , view field `aws.ec2.metrics.CPUUtilization.avg`, there are lot of entries with `99` but there is single entry with value `100`.

![](img/AWS/20260128111047.png)

> Flag: `100`

## AWS04
> What was the first root domain identified by GuardDuty findings that indicated crypto mining alert?

We switch back to `aws-*` Data view and search for `*crypto*`, add `aws.guardduty.title` field to the main table and open document with guardduty title `The EC2 instance i-06f9c69d1c1cb1ece queried a Bitcoin-related domain name`. There look for `dns` field, there is `dns.question.name` with value `pool.supportxmr.com` that is our answer.

![](img/AWS/20260128111329.png)

> Flag: `supportxmr.com`

## AWS05
> Seems like some funny internet magic money. What is the name of cryptomining application? (all lowercase)

For this we used [OSINT techniques](https://en.wikipedia.org/wiki/Open-source_intelligence) (Google, LLMs...) and found that domain `supportxmr.com` is related to `Monero` cryptocurrency mining service that is using `XMRig` application for mining coins.

> Flag: `xmrig`

## AWS06
> What is the full file path of the cryptominer executable detected by GuardDuty EBS scanning?

Back into `aws-*` Data view, filter on `cloud.instance.id : i-06f9c69d1c1cb1ece`, than  add `file.path` field to table view.

![](img/AWS/20260128144434.png)

> Flag: `/root/xmrig/build/xmrig`

## AWS07
> GuardDuty detected a script used to optimize the system for mining. What is the name of the script that enables huge memory pages?

From previous task, we see that one of the security risks detected is located at `/root/xmrig/scripts/enable_1gb_pages.sh`.

> Flag: `enable_1gb_pages.sh`

## AWS08
> An administrator terminated the suspicious EC2 instance. What is the arn of the admin who performed this action?

While still at `aws-*` Data view, search for `event.action:*StopInstance*`, find single `StopInstance` event, look at the document details for field `actor.identity.id`.

![](img/AWS/20260128145120.png)

> Flag: `arn:aws:iam::214900426653:root`

## AWS09
> At what time was this suspicious EC2 instance stopped by the administrator? (Format hh:mm:ss)

Look at the `@timestamp` from previous task.

> Flag: `22:18:33`

## AWS10
> What source country did the administrator logged in from when stopping the malicious instance?

From previous task, look at the `source.geo.country_name` field:

![](img/AWS/20260128145444.png)

> Flag: `Serbia`

## AWS11
> That instance did not ring a bell. What region it was running in?

From previous task look at the `cloud.region` field:

![](img/AWS/20260128145952.png)

> Flag: `eu-north-1`

## AWS12
> Weird. No running instances should be in that region. What user did set it up? (Give his full identity arn)

 In `aws-*` search for `event.action: RunInstances`, there is single event, check the `actor.entity.id` field.

 ![](img/AWS/20260128150326.png)

> Flag: `arn:aws:iam::214900426653:user/loan-apiuser`

## AWS13
> That is our legit loan application account, but used only for uploading forms from on-prem server. What EC2 instance type did the account choose for their cryptomining operation?

Log from previous task, field `aws.cloudtrail.flattened.request_parameters`, answer is in the JSON output, field `instanceType`.

![](img/AWS/20260128150809.png)

> Flag: `t3.large`

## AWS14
> What AMI ID was used for this instance?

Log from previous task, field `imageId`.

![](img/AWS/20260128150925.png)

> Flag: `ami-0068163775a114e89`

## AWS15
> What is assigned public IP address of newly created EC2 instance?

In `aws-*` Data view, search for `cloud.instance.id : "i-06f9c69d1c1cb1ece"` and open any document and look for `piblic.ip` field.

![](img/AWS/20260128151513.png)

> Flag: `16.170.218.1`

## AWS16
> What security group ID was associated with the attacker's EC2 instance at launch?

From previous task, look for field containing `security`.

![](img/AWS/20260128151621.png)

> Flag: `sg-0ab42b88d6eda3657`

## AWS17
> Before launching the instance, the attacker created a key pair for SSH access and attached to EC2. What is the name of the key pair created?

Back at the task [AWS14](#aws14), we see the field `keyName`.

> Flag: `testing_web_key`

## AWS18
> What is the fingerprint of the SSH key pair created by the attacker?

In `aws-*` search for `keyFingerprint`, single event found, look at event details:

![](img/AWS/20260128152308.png)

> Flag: `b4:f4:2a:90:b8:f8:fd:e4:0f:32:66:4a:bd:0c:00:63:ae:31:8b:bb`

## AWS19
> What IP address came these suspicious activities from?

From previous log, looks at the fields that contain `source`.

![](img/AWS/20260128152555.png)

> Flag: `138.199.21.200`

## AWS20
> What city is this IP originating from?

> Flag: `Tokyo`

## AWS21
> After logging in with the stolen credentials, the attacker might enumerated account permissions. Which IAM API call indicates the attacker was checking their identity? (event.action)

Consulted one of LLMs out there who pointed me to `https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html`.

> Flag: `GetCallerIdentity`

## AWS22
> Based on the user agent string in CloudTrail, what Linux distribution was the attacker using when executing AWS CLI commands? (lowercase without version)

In the previous task, look at the `user_agent.original` field.

![](img/AWS/20260128153332.png)

> Flag: `ubuntu`

## AWS23
> What is the access key ID that was used by the attacker for unauthorized access?

In the previous task, look at the `aws.cloudtrail.user_identity.access_key_id` field.

![](img/AWS/20260128154122.png)

> Flag: `AKIATECIQI6O6Y3CBDOH`

## AWS24
> Except creating the VM, keys and policies did the attacker created other backup access way? If yes, what is event.action of it. If no, type "no"

List all the `event.action` events for the user `actor.entity.id:"arn:aws:iam::214900426653:user/loan-apiuser"`, you will noticed `CreateUser` action.

![](img/AWS/20260128154917.png)

> Flag: `CreateUser`

## AWS25
> What is user name of this new bad boy?

Checking the details of the previous log, answer is in the `aws.cloudtrail.flattened.request_parameters` field.

![](img/AWS/20260128155144.png)

> Flag: `aws-testing`

## AWS26
> The attacker accessed sensitive company data in S3 objects. What is the name of the S3 bucket that was accessed?

Search for `event.action :ListObjects` in the `aws-*` with filter for `aws.cloudtrail.user_identity.arn:arn:aws:iam::214900426653:user/loan-apiuser`. Results are in the `aws.cloudtrail.flattened.request_parameters`

```
"{""list-type"":""2"",""bucketName"":""loan-applicants"",""encoding-type"":""url"",""delimiter"":""/"",""Host"":""loan-applicants.s3.eu-north-1.amazonaws.com""}"
```

> Flag: `loan-applicants`

## AWS27
> How many files did the attacker download from S3?

As previous task , just search for `event.action:GetObject`. Count the number of documents returned.

![](img/AWS/20260128155518.png)

> Flag: `7`

## AWS28
> What was name of the biggest S3 object the attacker downloaded? Access key of object based on S3 access logs.

Same search as previous task, just look at the filed `aws.cloudtrail.additional_eventdata` which document has the biggest `bytesTransferredOut`:

```
{SignatureVersion=SigV4, CipherSuite=TLS_AES_128_GCM_SHA256, bytesTransferredIn=0, AuthenticationMethod=AuthHeader, x-amz-id-2=0WUa+Fwuk5AfLucGfFiRvxHaNKgp8tHuwfn+qm8rYt9JFSaFG1A5tIiCYv+rvvqhOEPmUOSjUHe6R+gIhEMZ3olv9lSjqMdu, bytesTransferredOut=435}
```

> Flag: `applications/2648684d-7288-47bc-96fd-6d1348860cb3.json`

## AWS29
> What is the total size (in bytes) of all objects downloaded by the attacker?

Sum of all 7 documents `bytesTransferredOut`.

> Flag: `2975`

## AWS30
> What HTTP status code was returned for the attacker's S3 GetObject requests, confirming successful downloads?

Successful status is HTTP 200.

> Flag: `200`

## AWS31
> What is the legitimate public IP from which loan user usually connects?

In `aws-*` search for `NOT source.ip : "138.199.21.200"` with filter for `aws.cloudtrail.user_identity.arn:arn:aws:iam::214900426653:user/loan-apiuser` and look at the `source.ip`

![](img/AWS/20260128160237.png)

> Flag: `37.58.4.198`

## AWS32
> What is the most common operation that legitimate loan user do?

From previous task.

> Flag: `PutObject`

## AWS33
> Which Host fqdn is accessed when uploading data?

Previous search, in `field aws.cloudtrail.request_parameters`.
```
"{bucketName=loan-applicants, Host=loan-applicants.s3.eu-north-1.amazonaws.com, key=applications/8bade17c-0ce5-4276-a70a-870773cb6a6e.json}"
```

> Flag: `loan-applicants.s3.eu-north-1.amazonaws.com`

## AWS34
> Which region is this object located in?

From previous log, look for field `cloud.region`.

> Flag: `eu-north-1`

## AWS35
> Based on official Amazon IP address range for this region and S3 service, what IP range is used, with mask /22? (Answer X.X.X.X/XX)

Look at https://ip-ranges.amazonaws.com/ip-ranges.json, look for region `eu-north-1`, service `S3` and prefix that ends in `/22`. Helper script:

```
curl -s https://ip-ranges.amazonaws.com/ip-ranges.json | jq -r '.prefixes[] | select(.service=="S3" and .region=="eu-north-1" and ( .ip_prefix | endswith("/22")))'
```


> Flag: `3.5.216.0/22`

## AWS36
> What is the internal private IP in coolbank infrastructure that accesses this public range specifically around time loan-applicants bucket is updated?

In the Kibana Discover, select Data view `All logs`, and search for `destination.ip >= "3.5.216.0" and destination.ip <= "3.5.219.255"`, and select timeframe between `17:30` and `18:30`. There were total two IPs communicating with this range: `192.168.11.3` and `192.168.11.49`. Checking the [Network diagram](README.md#environment), we can see that `192.168.11.3` belongs to SIEM server and `192.168.11.49` to LOAN server.

> Flag: `192.168.11.49`

## AWS37
> What is the hostname of the device with this IP?

Info in previous task.

> Flag: `LOAN`