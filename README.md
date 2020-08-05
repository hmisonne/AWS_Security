# Cloud Security - Secure the Recipe Vault Web Application
 
Project goals:
 
* Deploy and assess a simple web application environment’s security posture
* Test the security of the environment by simulating attack scenarios and exploiting cloud configuration vulnerabilities
* Implement monitoring to identify insecure configurations and malicious activity 
* Apply methods learned in the course to harden and secure the environment
* Design a DevSecOps pipeline
 
Instructions for this project are available in [this GitHub repo](https://github.com/udacity/nd063-c3-design-for-security-project-starter)

## Exercise 1 - Review Architecture Diagram
 
![base environment](starter/AWS-WebServiceDiagram-v1-insecure.png)
Poor practices:
- The current infrastructure is not using private subnets which expose the servers to malicious traffic. The web server instance should be in a private subnet with firewall in place to only allow traffic from the AppLoadBalancer SG. This could be done by setting up the Security Group rules. 
The  AppLoadBalancer SG should also have a rule to only allow traffic from 0.0.0.0 port 80 and 443.

- The users are not authenticated. To secure this app and differentiate the users who have a privileged access, the users will need to be authenticated with an External Identity Provider. Once authenticated, the users will be provided an IAM role with temporary API credentials that will allow them to get access to the API.

- The S3 buckets are not encrypted. To add a layer of encryption the default encryption should be set up on the S3 bucket. 
The S3 buckets should also have bucket policy that allows only specific role to get access to the content.


## Exercise 2 - Identify Vulnerabilities By Reviewing Security Monitoring Tools

#### AWS Config: Non Compliant Rules 

- Logging is enabled for S3 buckets
- S3 buckets have policies that require requests to use Secure Socket Layer (SSL). 
- S3 bucket either has Amazon S3 default encryption enabled
- Amazon GuardDuty is enabled in your AWS account and region. 
- EC2 instances are managed by AWS Systems Manager. 
- EBS volumes that are in an attached state are encrypted.
- Checks whether HTTP to HTTPS redirection is configured on all HTTP listeners of Application Load Balancers.

#### Amazon Inspector: Findings 

- Web Service EC2 Instance is configured to allow users to log in with root credentials over SSH, without having to use a command authenticated by a public key. This increases the likelihood of a successful brute-force attack.
	- Recommendation: disable SSH root account logins
- Web Service EC2 Instance is configured to support password authentication over SSH. Password authentication is susceptible to brute-force attacks and should be disabled in favor of key-based authentication where possible.
	- Recommendation: Disable password authentication over SSH on your EC2 instances and enable support for key-based authentication instead.
- On Web Service EC2 Instance, process 'systemd-netwo' is listening on UDP port 68 which is associated with 'DHCP' and is reachable from the internet
- On Web Service EC2 Instance, process 'sshd' is listening on TCP port 22 which is associated with 'SSH' and is reachable from the internet
	- Recommendation: edit the Security Group to remove access from the internet on port 22 + 68

#### Security Hub: Findings

- S3 Secret + Free Recipe + VPC flow log buckets should have server-side encryption enabled: 
- security groups WebAppSG allow ingress from 0.0.0.0/0 to port 3389 & 22
- Attached EBS volumes should be encrypted at-rest for the Web Service Instance
 
## Exercise 3 - Attack Simulation

Run scripts that will simulate the following attack conditions: Making an SSH connection to the application server using brute force password cracking. 
Capturing secret recipe files from the s3 bucket using stolen API keys.

1. What findings were detected related to the brute force attack?
- GuardDuty should have found that Web Service instance allows SSH password and Web Service instance security group allows login SSH traffic and is open to the public.

2. Research the AWS Guard Duty documentation page and explain how GuardDuty may have detected this attack - i.e. what was its source of information?
- GuardDuty is collecting and analyzing the data coming from: VPC flow logs, AWS CloudTrail management event logs, Cloudtrail S3 data event logs, and DNS logs.
- GuardDuty should have detected the attack through the VPC flow logs.


## Exercise 4 - Implement Security Hardening

### Remediation plan

1. Identify 2-3 changes that can be made to our environment to prevent an ssh brute force attack from the internet.

- Remove SSH inbound rule on the WebAppSG Security Group.
- Create a private subnet inside the VPC to host the Web Service instance and allow inbound traffic from the application load balancer
- Update Network ACL in the private subnet to block inbound SSH traffic, 
- Block traffic from 0.0.0.0/0 except from port 80 (to effectively block port Range 22)
- Update the AppLoadBalancerSG to only allow outbound traffic to the WebAppSG
- Update Security Group to 

2. Neither instance should have had access to the secret recipes bucket, in the even that instance API credentials were compromised how could we have prevented access to sensitive data.

- Allow Default encryption
- Update S3 bucket policy to only allow Read operations from a specific instance. 
- Update the c3-app-InstanceRole IAM role policy to only allow read opeations to the S3 public recipe buckets (resource).


### Questions and Analysis

1. What additional architectural change can be made to reduce the internet-facing attack surface of the web application instance.
- Move the web server instance from the public subnet to a private subnet
- Add IAM policy to bucket to restrict read operation from a specific role.
- Create Network ACL rules to ban specific traffic
- Add a NAT gateway or a Web Proxy Layer to restrict egress traffic
- Set up web Application Firewalls to block attacks such as Cloud Front.

2. Assuming the IAM permissions for the S3 bucket are still insecure, would creating VPC private endpoints for S3 prevent the unauthorized access to the secrets bucket.
- Moving the endpoint for S3 to a private subnet would only prevent traffic coming from outside the VPC.

3. Will applying default encryption setting to the s3 buckets encrypt the data that already exists?
- No, There is no change to the encryption of the objects that existed in the bucket before default encryption was enabled. 

4. The changes you made above were done through the console or CLI; describe the outcome if the original cloud formation templates are applied to this environment?
- The new cloudformation will overwrite the changes done on the Security Groups, SSH password disabled, IAM role restrictions.
In order to apply the changes to the environment, the cloudformation template would need to be updated.

## Exercise 5 - Designing a DevSecOps Pipeline

### Design a DevSecOps pipeline

![DevSecOpsPipline](screenshots/DevSecOpsPipline.png)


### Tools and Documentation

#### Scan infrastructure as code templates

Appropriate Tools:

- Checkov
- TFLint
- Terrafirma
- Accurics
- CloudSploit

Example vulnerability
- VPC flow logging disabled
- VPC security group rules ingress from '0.0.0.0/0' traffic not restricted 
- S3 bucket not encrypted
- EBS volume encryption disabled

#### Scan AMI’s or containers for OS vulnerabilities

Appropriate Tools:
- Anchore
- Dagda
- OpenSCAP
- Sysdig Falco

Example vulnerability
- Embedded clear text secrets
- Use of untrusted images
- Image Configuration Defects (image built from Dockerfiles that have exposed port 22)

#### Scan an AWS environment for cloud configuration vulnerabilities

Appropriate Tools:
- AWS Config
- Cloud Custodian
- Prowler

Example vulnerability
- Configuration changes on KMS, IAM policy
- Data not encrypted
