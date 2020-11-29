## the vulnerability policy attestor checks whether the 
## vulnerabilities discovered by the scanner will pass the
## policy allowable vulnerabilties in an image.
resource "google_cloud_run_service" "vulnerability_policy_attestor" {
  name     = "vulnerability-policy-attestor"
  location = "europe-west1"

  template {
    spec {
      service_account_name = google_service_account.vulnerability_policy_attestor.email
      containers {
        image = "gcr.io/binx-io-public/gcr-kritis-signer:0.0.3"
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
          value = file("policy.yaml")
        }
      }
    }
  }
  depends_on = [google_project_service.run]
}

## the service account and associated roles required to create attestations
resource "google_service_account" "vulnerability_policy_attestor" {
  account_id   = "vulneratility-policy-attestor"
  display_name = "Vulnerability policy attestor"
}

resource "google_project_iam_member" "vulnerability_policy_attestor_containeranalysis_notes_occurrences_viewer" {
  role    = "roles/containeranalysis.notes.occurrences.viewer"
  member  = "serviceAccount:${google_service_account.vulnerability_policy_attestor.email}"
  project = var.project
}

resource "google_project_iam_member" "vulnerability_policy_attestor_containeranalysis_notes_attacher" {
  role    = "roles/containeranalysis.notes.attacher"
  member  = "serviceAccount:${google_service_account.vulnerability_policy_attestor.email}"
  project = var.project
}

resource "google_project_iam_member" "vulnerability_policy_attestor_containeranalysis_occurrences_editor" {
  # required to create occurrences.
  role    = "roles/containeranalysis.occurrences.editor"
  member  = "serviceAccount:${google_service_account.vulnerability_policy_attestor.email}"
  project = var.project
}

# define who can invoke this attestor
resource "google_service_account" "vulnerability_policy_attestor_invoker" {
  account_id   = "vlnrblty-plcy-attstr-invoker"
  display_name = "Vulnerability policy attestor invoker"
}

resource "google_cloud_run_service_iam_binding" "vulnerability_policy_attestor_invoker" {
  location = google_cloud_run_service.vulnerability_policy_attestor.location
  project  = google_cloud_run_service.vulnerability_policy_attestor.project
  service  = google_cloud_run_service.vulnerability_policy_attestor.name
  role     = "roles/run.invoker"
  members = [
    "serviceAccount:${google_service_account.vulnerability_policy_attestor_invoker.email}"
  ]
}

# define who is allowed to assume the role of invoker
resource "google_service_account_iam_binding" "vulnerability_policy_attestor_invoker_token_creator" {
  service_account_id = google_service_account.vulnerability_policy_attestor_invoker.name
  role               = "roles/iam.serviceAccountTokenCreator"
  members = [
    "serviceAccount:service-${data.google_project.current.number}@gcp-sa-pubsub.iam.gserviceaccount.com"
  ]
  depends_on = [google_project_service.pubsub]
}

# subscribe the attestor to the container analysis occurrences events
resource "google_pubsub_subscription" "vulnerability_policy_attestor" {
  name  = "vulnerability-policy-attestor"
  topic = "projects/${var.project}/topics/container-analysis-occurrences-v1"

  ack_deadline_seconds = 30

  push_config {
    push_endpoint = "${google_cloud_run_service.vulnerability_policy_attestor.status[0].url}/event"
    oidc_token {
      service_account_email = google_service_account.vulnerability_policy_attestor_invoker.email
    }
  }
  depends_on = [google_project_service.pubsub]
}

# KMS Key identifying the vulnerability scan attestor
resource "google_kms_key_ring" "vulnerability_policy_attestors" {
  name       = "vulnerability_policy_attestors"
  location   = "eur4"
  depends_on = [google_project_service.cloudkms]
}

resource "google_kms_crypto_key" "vulnerability_policy_attestor" {
  name     = "vulnerability-attestor-${random_id.vulnerability_policy_attestor.b64_url}"
  key_ring = google_kms_key_ring.vulnerability_policy_attestors.id
  purpose  = "ASYMMETRIC_SIGN"

  version_template {
    algorithm = "EC_SIGN_P384_SHA384"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "random_id" "vulnerability_policy_attestor" {
  byte_length = 2
}


data "google_kms_crypto_key_version" "vulnerability_policy_attestor" {
  crypto_key = google_kms_crypto_key.vulnerability_policy_attestor.self_link
}

# allow the attestor to use this key to sign attestations
resource "google_kms_crypto_key_iam_binding" "vulnerability_policy_attestor_signer_verifier" {
  crypto_key_id = google_kms_crypto_key.vulnerability_policy_attestor.id
  role          = "roles/cloudkms.signerVerifier"

  members = [
    "serviceAccount:${google_service_account.vulnerability_policy_attestor.email}"
  ]
}

locals {
  algorithms = { ## avoid continuous update of google_binary_authorization_attestor
    "EC_SIGN_P384_SHA384" = "ECDSA_P384_SHA384"
  }
}

# Define the attestor to be and attestor of vulnerability policies
resource "google_binary_authorization_attestor" "vulnerability_policy" {
  name = "vulnerability-policy"
  attestation_authority_note {
    note_reference = google_container_analysis_note.passed_vulnerability_policy.name
    public_keys {
      id = data.google_kms_crypto_key_version.vulnerability_policy_attestor.id
      pkix_public_key {
        public_key_pem      = data.google_kms_crypto_key_version.vulnerability_policy_attestor.public_key[0].pem
        signature_algorithm = local.algorithms[data.google_kms_crypto_key_version.vulnerability_policy_attestor.public_key[0].algorithm]
      }
    }
  }
}

# define how can view the attestors
resource "google_binary_authorization_attestor_iam_binding" "binaryauthorization_attestors_viewer" {
  project  = google_binary_authorization_attestor.vulnerability_policy.project
  attestor = google_binary_authorization_attestor.vulnerability_policy.name
  role     = "roles/binaryauthorization.attestorsViewer"
  members = [
    "serviceAccount:${google_service_account.vulnerability_policy_attestor.email}"
  ]
}

resource "google_container_analysis_note" "passed_vulnerability_policy" {
  name = "passed-vulnerability-policy"

  short_description = "image passed vulnerability policy"
  long_description  = <<EOF
attached to an image which passed the vulnerability 
scan without violating the security policy.
EOF

  attestation_authority {
    hint {
      human_readable_name = "vulnerability policy attestors"
    }
  }
}

data "google_project" "current" {
  project_id = var.project
}
