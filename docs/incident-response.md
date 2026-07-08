# Incident Response - Security Scenarios

This document walks through five realistic security scenarios this
platform is designed to catch, using the controls built in Stages 1-4
(IAM, CloudTrail/KMS, GuardDuty, Security Hub, and AWS Config). Each
scenario follows the same structure: Detection, Investigation,
Remediation, and Security Impact. These are written as safe, descriptive
walkthroughs - no destructive actions are performed against a live
account as part of this documentation.

## Scenario 1: Public S3 Bucket

**Setup:** A bucket policy or ACL is changed (by mistake, or by an
attacker with sufficient permissions) to allow public read access.

**Detection:** AWS Config's `s3-bucket-public-read-prohibited` rule
re-evaluates the bucket within minutes of the change and marks it
`NON_COMPLIANT`. Security Hub's AFSBP standard also has its own overlapping
check (`S3.8`) that would flag the same bucket. If GuardDuty S3 Protection
were enabled, unusual access patterns to the bucket from unfamiliar
locations could additionally generate a finding.

**Investigation:** CloudTrail is checked for the specific `PutBucketAcl`
or `PutBucketPolicy` API call, which identifies exactly who (or what role)
made the change, from what IP address, and at what time. The bucket's
access logs (if enabled) are reviewed for any requests that occurred while
it was public.

**Remediation:** Restore the bucket's public access block settings and
tighten the bucket policy back to least-privilege, then confirm the
Config rule returns to `COMPLIANT`.

**Security Impact:** A public bucket can expose sensitive data to anyone
on the internet, and depending on content, could constitute a reportable
data breach.

## Scenario 2: Overly Permissive IAM Policy

**Setup:** A new or edited IAM policy grants `"Action": "*"` and
`"Resource": "*"` (or otherwise unnecessarily broad permissions) to a
user or role that does not need it.

**Detection:** AWS Config's `iam-policy-no-statements-with-admin-access`
rule flags any managed or inline policy containing an admin-style
statement. Security Hub's AFSBP standard includes a related IAM check
for policies attached directly to users instead of through groups/roles.

**Investigation:** CloudTrail's `CreatePolicy` / `PutUserPolicy` /
`AttachUserPolicy` events show who created or attached the policy. IAM
Access Analyzer (a recommended enhancement) would additionally show
whether the policy grants access to resources outside the account.

**Remediation:** Replace the broad policy with a least-privilege policy
scoped to only the specific actions and resources required, following the
same pattern used for the Developers/Security groups in `iam.tf`.

**Security Impact:** An overly permissive policy dramatically increases
the 'blast radius' if that user's or role's credentials are ever
compromised - turning a single stolen credential into full account
compromise.

## Scenario 3: Unencrypted Resource

**Setup:** A new S3 bucket is created without default server-side
encryption enabled.

**Detection:** AWS Config's
`s3-bucket-server-side-encryption-enabled` rule marks the bucket
`NON_COMPLIANT` as soon as it is evaluated.

**Investigation:** CloudTrail's `CreateBucket` event identifies who
created the bucket and when, which helps determine whether it was a
one-off manual action (a process gap) or came from an automated pipeline
(a template/module that needs fixing at the source).

**Remediation:** Apply a default encryption configuration to the bucket
(SSE-S3 or SSE-KMS depending on data sensitivity), matching the pattern
used for the CloudTrail and Config log buckets in this project.

**Security Impact:** Unencrypted data at rest increases exposure if the
underlying storage is ever accessed outside of normal AWS API controls,
and commonly fails compliance audits outright.

## Scenario 4: Security Group Open to the Internet

**Setup:** A security group is created or modified with an inbound rule
allowing SSH (port 22) from `0.0.0.0/0`.

**Detection:** AWS Config's `restricted-ssh` rule
(`INCOMING_SSH_DISABLED`) flags the security group as `NON_COMPLIANT`.
If an instance using that security group is then actually probed or
attacked, GuardDuty may separately raise a finding such as
`Recon:EC2/PortProbeUnprotectedPort` or, if a brute-force attempt
succeeds, `UnauthorizedAccess:EC2/SSHBruteForce`.

**Investigation:** CloudTrail's `AuthorizeSecurityGroupIngress` event
shows who opened the port and when. VPC Flow Logs (a recommended
enhancement) would show exactly which external IP addresses attempted to
connect.

**Remediation:** Restrict the rule to a specific, known IP range (or
remove direct SSH entirely in favor of AWS Systems Manager Session
Manager, which requires no open inbound ports at all).

**Security Impact:** An open SSH port is one of the most commonly
scanned-for misconfigurations on the internet and is frequently exploited
within minutes of exposure by automated botnets.

## Scenario 5: AWS Config Detecting a Non-Compliant Resource (General
Case)

**Setup:** Any resource drifts out of its intended, secure configuration
over time - for example, someone temporarily disables a setting to
troubleshoot an issue and forgets to re-enable it.

**Detection:** Because the Configuration Recorder in `config.tf` watches
`all_supported` resource types continuously, drift is caught on the very
next configuration change, not during the next scheduled audit (which,
in many organizations without Config, might be months later).

**Investigation:** The resource's configuration timeline in the Config
console shows every historical state, making it possible to pinpoint
exactly when it became non-compliant and correlate that timestamp with
CloudTrail for the responsible API call.

**Remediation:** Fix the specific drifted setting, and consider whether a
Config Remediation Configuration (auto-remediation) would prevent the same
drift from causing risk in the future.

**Security Impact:** Continuous compliance monitoring converts security
policy from a document nobody re-reads into an enforced, living control -
which is precisely the gap AWS Config is designed to close.

## How These Scenarios Surface in Security Hub

Every finding described above - whether originally generated by AWS
Config or GuardDuty - is automatically normalized and displayed in
Security Hub with a consistent severity rating, affected resource ARN,
and a remediation link, giving one analyst a single place to triage all
five scenario types without switching consoles.
