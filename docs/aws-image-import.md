# AWS image import setup

`atakit cloud image upload` and AWS deployments upload the disk to S3, then
call `aws ec2 import-snapshot`. AWS uses a separate IAM role named `vmimport`
to read that disk. IAM is AWS's permission system. `atakit` does not create
or change this role.

If AWS reports `The service role vmimport provided does not exist or does not
have sufficient permissions`, check the role in the account used by the upload:

```sh
aws sts get-caller-identity
aws iam get-role --role-name vmimport
aws iam list-role-policies --role-name vmimport
aws iam list-attached-role-policies --role-name vmimport
```

Use the same `AWS_PROFILE` as the upload. The provider name in the atakit
configuration does not select an AWS CLI profile. If these commands return
`AccessDenied`, ask the account administrator to inspect the role; that error
does not prove the role is absent.

## Create a missing role

Create these files in a working directory. Replace `IMPORT_BUCKET` in the
permissions below with the bucket from the upload's `aws s3 cp` command
(shown when running atakit with `--verbose`). These examples use the standard
AWS partition, whose resource names start with `arn:aws:`.

Save this as `trust-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "vmie.amazonaws.com"},
    "Action": "sts:AssumeRole",
    "Condition": {"StringEquals": {"sts:Externalid": "vmimport"}}
  }]
}
```

If `get-role` returned `NoSuchEntity`, create the role:

```sh
aws iam create-role --role-name vmimport \
  --assume-role-policy-document file://trust-policy.json
```

If the role already exists, inspect its `AssumeRolePolicyDocument`. It must
allow the trust statement above. Have the administrator merge missing rules
with its existing trust policy and retain any account restrictions.

Save this as `import-policy.json`, replacing both instances of `IMPORT_BUCKET`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetBucketLocation", "s3:ListBucket"],
      "Resource": "arn:aws:s3:::IMPORT_BUCKET"
    },
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::IMPORT_BUCKET/vms/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ec2:ModifySnapshotAttribute",
        "ec2:CopySnapshot",
        "ec2:RegisterImage",
        "ec2:Describe*"
      ],
      "Resource": "*"
    }
  ]
}
```

Attach it using a policy name unique to that bucket. Set `import_bucket` first:

```sh
import_bucket='REPLACE_WITH_IMPORT_BUCKET'
aws iam put-role-policy --role-name vmimport \
  --policy-name "atakit-import-${import_bucket}" \
  --policy-document file://import-policy.json
```

The policy permits reads only from this bucket's `vms/` directory. Use a
separate policy for another bucket so existing imports keep their access.
The EC2 permissions follow AWS's documented service role policy.

## Check the identity running atakit

The identity running atakit also needs `iam:PassRole` on the `vmimport` role,
in addition to its S3 and EC2 permissions. Ask the administrator to add this
statement to that identity's permissions, replacing `ACCOUNT_ID`:

```json
{
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": "arn:aws:iam::ACCOUNT_ID:role/vmimport"
}
```

Allow time for IAM changes to take effect, then repeat the original atakit
command. If the error persists, check bucket policies and account restrictions
for explicit denials. AWS Security Token Service (STS) must be enabled in the
import region. Customer-managed encryption keys also need permissions for
`vmimport`; see the AWS guide below.

Source: [AWS VM Import/Export required permissions](https://docs.aws.amazon.com/vm-import/latest/userguide/required-permissions.html).
