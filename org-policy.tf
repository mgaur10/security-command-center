/**
 * Copyright 2022 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


## NOTE: This provides PoC demo environment for various use cases ##
##  This is not built for production workload ##

module "org-policy1" {
  source      = "terraform-google-modules/org-policy/google"
  policy_for  = "project"
  project_id  = google_project.demo_project.project_id
  constraint  = "compute.requireShieldedVm"
  policy_type = "boolean"
  enforce     = false
}

module "org-policy2" {
  source      = "terraform-google-modules/org-policy/google"
  policy_for  = "project"
  project_id  = google_project.demo_project.project_id
  constraint  = "compute.requireOsLogin"
  policy_type = "boolean"
  enforce     = false
}

module "org-policy3" {
  source      = "terraform-google-modules/org-policy/google"
  policy_for  = "project"
  project_id  = google_project.demo_project.project_id
  constraint  = "iam.disableServiceAccountKeyCreation"
  policy_type = "boolean"
  enforce     = false
}

module "org-policy4" {
  source      = "terraform-google-modules/org-policy/google"
  policy_for  = "project"
  project_id  = google_project.demo_project.project_id
  constraint  = "iam.disableServiceAccountCreation"
  policy_type = "boolean"
  enforce     = false
}

resource "google_project_organization_policy" "project_policy_list_allow_all" {
  for_each     = toset(var.constraints)
  project    = google_project.demo_project.project_id
  constraint = each.value
  list_policy {
    allow {
      all = true
    }
  }
}