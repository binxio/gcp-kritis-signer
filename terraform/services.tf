resource google_project_service "container" {
  service            = "container.googleapis.com"
  disable_on_destroy = false
}

resource google_project_service "containeranalysis" {
  service            = "containeranalysis.googleapis.com"
  disable_on_destroy = false
}

resource google_project_service "containerscanning" {
  service            = "containerscanning.googleapis.com"
  disable_on_destroy = false
}

resource google_project_service "binaryauthorization" {
  service            = "binaryauthorization.googleapis.com"
  disable_on_destroy = false
}

resource google_project_service "containerregistry" {
  service            = "containerregistry.googleapis.com"
  disable_on_destroy = false
}
