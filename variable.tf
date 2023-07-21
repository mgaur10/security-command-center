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


variable "organization_id" {
}

variable "billing_account" {
}

variable "folder_name" {
}


variable "demo_project_id" {
}


variable "vpc_network_name" {
}


variable "network_zone" {
}


variable "network_region" {
}



variable "proxy_access_identities" {
  description = "Identity who require access to the SQL proxy, and database.  Every identity should be prefixed with the type, for example user:, serviceAccount: and/or group:"
  type        = string
  # default     = "user:abc@xyz.com"
}




variable "labels" {
  description = "Labels, provided as a map"
  type        = map(string)
}


#GKE - demo



variable "name" {
  type        = string
  description = "Name given to the new GKE cluster"
  default     = "ktd-test-online-boutique2"
}

variable "namespace" {
  type        = string
  description = "Kubernetes Namespace in which the Online Boutique resources are to be deployed"
  default     = "default"
}

variable "filepath_manifest" {
  type        = string
  description = "Path to the Kubernetes manifest that defines the Online Boutique resources"
  default     = "appmod-module/release/kubernetes-manifests.yaml"
}

variable "memorystore" {
  type        = bool
  description = "If true, Online Boutique's in-cluster Redis cache will be replaced with a Google Cloud Memorystore Redis cache"
  default     = false
}


variable "global_policy_evaluation_mode" {
  description = "(optional) - Controls the evaluation of a Google-maintained global admission policy\nfor common system-level images. Images not covered by the global\npolicy will be subject to the project admission policy. Possible values: [\"ENABLE\", \"DISABLE\"]"
  type        = string
  default     = "ENABLE"
}

variable "constraints" {
  description = "The list of constraints to disable"
  default     = ["compute.trustedImageProjects","compute.vmExternalIpAccess","compute.restrictSharedVpcSubnetworks","compute.restrictSharedVpcHostProjects","compute.restrictVpcPeering","compute.vmCanIpForward","iam.allowedPolicyMemberDomains"]
  type        = list(string)
}
