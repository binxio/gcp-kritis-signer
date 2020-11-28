# How to automate container image signing for use in Google Binary Authorization

Google Binary Authorization allows you to control which images are
  allowed to run on your Kubernetes cluster. It allows you to name the
  images explicitly, or required images to be signed off for use. In this
  blog I will should you how to automate signing off images which pass the
  vulnerability scan policy.

<!--more -->
When you create a GKE cluster with binary authorization enabled, you specify
  which images to run either by name or by the fact that somebody vouched
  for the image.

## authorize images by name
The following policy only allow images from the GCR registries in
  the us and the eu from the project `binx-io-public`:

```yaml
globalPolicyEvaluationMode: ENABLE
defaultAdmissionRule:
  evaluationMode: ALWAYS_DENY
  enforcementMode: ENFORCED_BLOCK_AND_AUDIT_LOG
admissionWhitelistPatterns:
- namePattern: gcr.io/binx-io-public/*
- namePattern: eu.gcr.io/binx-io-public/*
```

## authorize vouched images
The following policy only allow images which are vouched
  for by both the `qa` and `vulnerability-policy` attestors:

```yaml
globalPolicyEvaluationMode: ENABLE
defaultAdmissionRule:
  evaluationMode: ALWAYS_DENY
  enforcementMode: ENFORCED_BLOCK_AND_AUDIT_LOG
requireAttestationsBy:
  - projects/binx-io-public/attestors/vulnerability-policy
```

An attestor is somebody who affirms that the image is genuine by
  signing a written statement. In the above case we state that we will only
  run images that have been attested to pass a security vulnerabilities policy.

## container vulnerability scanning
When you enable the container scanning service, each image pushed to
  the registry is scanned for vulnerabilities. For instance,

```bash
export PROJECT_ID=binx-io-public

docker pull alpine:3.2
docker tag alpine:3.2 gcr.io/$PROJECT_ID/alpine:3.2
docker push  gcr.io/$PROJECT_ID/alpine:3.2
gcloud beta container images list-tags gcr.io/$PROJECT_ID/alpine --show-occurrences
```
```
DIGEST        TAGS    TIMESTAMP            VULNERABILITIES  VULNERABILITY_SCAN_STATUS
ddac200f3ebc  3.2     2019-01-30T23:20:12  HIGH=1           FINISHED_SUCCESS
```

To show to discovered vulnerability details, type:

```bash
IMAGE_DIGEST=$(docker inspect \
	alpine:3.2 --format '{{range .RepoDigests}}{{printf "https://%s\n" .}}{{end}}' | \
	grep $PROJECT_ID/)

curl -G -sS -H "Authorization: Bearer $(gcloud auth print-access-token)"  \
   --data-urlencode "filter=kind=\"VULNERABILITY\" AND resourceUrl=\"$IMAGE_DIGEST\"" \
   https://containeranalysis.googleapis.com/v1/projects/$PROJECT_ID/occurrences
{
  "occurrences": [
    {
      "name": "projects/binx-io-public/occurrences/8331ad53-25a9-4818-b815-2aee50bf7db4",
      "resourceUri": "https://gcr.io/binx-io-public/alpine@sha256:ddac200f3ebc9902fb8cfcd599f41feb2151f1118929da21bcef57dc276975f9",
      "noteName": "projects/goog-vulnz/notes/CVE-2016-6301",
      "kind": "VULNERABILITY",
      "createTime": "2020-11-10T13:01:39.103385Z",
      "updateTime": "2020-11-10T13:01:39.103385Z",
      "vulnerability": {
        "severity": "HIGH",
        "cvssScore": 7.8,
        "packageIssue": [
          {
            "affectedCpeUri": "cpe:/o:alpine:alpine_linux:3.2",
            "affectedPackage": "busybox",
            "affectedVersion": {
              "name": "1.23.2",
              "revision": "r3",
              "kind": "NORMAL",
              "fullName": "1.23.2-r3"
            },
            "fixedCpeUri": "cpe:/o:alpine:alpine_linux:3.2",
            "fixedPackage": "busybox",
            "fixedVersion": {
              "name": "1.24.2",
              "revision": "r1",
              "kind": "NORMAL",
              "fullName": "1.24.2-r1"
            },
            "fixAvailable": true
          }
        ],
        "shortDescription": "CVE-2016-6301",
        "longDescription": "NIST vectors: AV:N/AC:L/Au:N/C:N/I:N/A:C",
        "effectiveSeverity": "HIGH",
        "fixAvailable": true
      }
    }
  ]
}
```
