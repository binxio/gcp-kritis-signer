# GCR kritis signer

GCR kritis signer is a service that creates an attestation for a container image if it passes the vulnerability policy. 
  it will accept direct check and sign requests, but it can be subscribed to the topic
  `container-analysis-occurrence-v1`. When a container vulnerability analysis has completed, it checks the vulnerabilities 
  against the policy. When it passes the policy, it creates an attestation.
  
## api specification
The following tables shows the available operations from the [api](./api-specification.yaml):

| path            | description               |
| --------------- | --------------------------|
| /check          | checks the specified image against the policy |
| /check-and-sign | checks and signs if the image passes the policy |
| /event          | if the event indicates the completion of a vulnerability scan, checks and signs the image |

    
/check and /check-and-sign accept the following request message:

```json
{ 
    "image": "gcr.io/project/alpine@sha256:f86657a463e3de9e5176e4774640c76399b2480634af97f45354f1553e372cc9",
}
```

If the image passes the policy the response message will be: 
```json
{
    "image": "gcr.io/project/alpine@sha256:f86657a463e3de9e5176e4774640c76399b2480634af97f45354f1553e372cc9",
    "status": "ok"
}
```
If it does not pass the policy, the message will be. 
```json
{
  "status": "failed",
  "image": "gcr.io/project/a27@sha256:f86657a463e3de9e5176e4774640c76399b2480634af97f45354f1553e372cc9",
  "violations": [
    "found unfixable CVE projects/goog-vulnz/notes/CVE-2018-18344 in gcr.io/..., which has severity MEDIUM exceeding max unfixable severity LOW",
    "found unfixable CVE projects/goog-vulnz/notes/CVE-2020-1751 in gcr.io/..., which has severity MEDIUM exceeding max unfixable severity LOW",
  ]
}
```
/event accepts a normal pubsub event message:

```json
{
  "subscription": "vulnerability-attestor-container-analysis-occurrences",
  "message": {
    "data": "eyJuYW1lIjoicHJvamVjdHMvcHJvamVjdC9vY2N1cnJlbmNlcy9mNjJmMWU1MC1lMGUyLTQ3ZWYtOTI1ZC1iZDc5OTA1YWI4MmQiLCJraW5kIjoiRElTQ09WRVJZIiwibm90aWZpY2F0aW9uVGltZSI6IjIwMjAtMTEtMDZUMTU6MDM6NTAuNTMxMDgyWiJ9",
    "id": "1681150847368976"
  }
}
```

where the data will be provided by the container analysis service:
```json
{
  "name": "projects/project/occurrences/f62f1e50-e0e2-47ef-925d-bd79905ab82d",
  "kind": "DISCOVERY",
  "notificationTime": "2020-11-06T15:03:50.531082Z"
}
```
## configuration
You configure the GCP signer using the following environment variables and/or command options:

| name                         | option            | description                                 | required |
| ---------------------------- | ----------------  | ------------------------------------------- | -------- |
| ATTESTATION\_POLICY           | -policy           | policy defining acceptable vulnerabilities  | yes |
| ATTESTATION\_NOTE\_NAME        | -note-name        | name of the note to attest                  | yes |
| ATTESTATION\_KMS\_KEY          | -kms-key          | KMS key version to use to sign              | yes |
| ATTESTATION\_DIGEST\_ALGORITHM | -digest-algorithm | digest algorithm used                       | yes |
| ATTESTATION\_PROJECT          | -project          | GCP project to store attestation            | no, default it uses the image project |
| ATTESTATION\_OVERWRITE        | -overwrite        |overwrite existing attestations              | no, default false | 
 
## deployment
The GCP signer can be deployed using the following terraform configuration:

```tf
resource "google_cloud_run_service" "vulnerability_policy_attestor" {
  name     = "vulnerability-policy-attestor"
  location = "europe-west1"

  template {
    spec {
      service_account_name = google_service_account.vulnerability_policy_attestor.email
      containers {
        image = "gcr.io/binx-io-public/gcp-kritis-signer:latest
        env {
          name  = "ATTESTATION_PROJECT"
          value = var.project
        }
        env {
          name  = "ATTESTATION_NOTE_NAME"
          value = google_container_analysis_note.passed_vulnerability_policy.id
        }
        env {
          name  = "ATTESTATION_KMS_KEY"
          value = replace(data.google_kms_crypto_key_version.vulnerability_policy_attestor.id, "///cloudkms.googleapis.com/[^/]*//", "")
        }
        env {
          name  = "ATTESTATION_DIGEST_ALGORITHM"
          value = "SHA384"
        }
        env {
          name  = "ATTESTATION_OVERWRITE"
          value = "true"
        }
        env {
          name  = "ATTESTATION_POLICY"
          value = <<EOF
apiVersion: kritis.grafeas.io/v1beta1
kind: VulnzSigningPolicy
metadata:
  name: image-vulnerability-policy
spec:
  imageVulnerabilityRequirements:
    maximumFixableSeverity: MEDIUM
    maximumUnfixableSeverity: MEDIUM
    allowlistCVEs:
    - projects/goog-vulnz/notes/CVE-2020-10543
    - projects/goog-vulnz/notes/CVE-2020-10878
    - projects/goog-vulnz/notes/CVE-2020-14155
EOF
        }
      }
    }
  }
```
