cd ##  /**
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

#files/statup.sh
#!/bin/bash
sudo apt-get update -y
sudo apt-get install -y git wget curl make
sudo git clone https://github.com/mgaur10/security-command-center.git /tmp/security-command-center/
curl etd-malware-trigger.goog
curl etd-coinmining-trigger.goog
curl etd-phishing-trigger.goog
sudo tar xvzf /tmp/security-command-center/inactivated_miner/inactivated_miner.tar.gz
sudo chmod 777 inactivated_miner
sudo timeout 15s sudo ./inactivated_miner && sudo make && sudo make install
# miner version 1
sudo tar -xf /tmp/security-command-center/inactivated_miner/inactivated_minerv1.tar
sudo chmod 777 inactivated_minerv1
sudo timeout 20s sudo ./inactivated_minerv1
counter=10
while [ $counter -gt 0 ];
do
    sleep 120
    sudo timeout 20s sudo ./inactivated_miner
    curl etd-malware-trigger.goog
    curl etd-coinmining-trigger.goog
    curl etd-phishing-trigger.goog
    sudo timeout 20s sudo ./inactivated_minerv1;
    ((counter--))
done
sudo rm -rf /tmp/security-command-center
sudo rm inactivated_minerv1
sudo rm inactivated_miner
