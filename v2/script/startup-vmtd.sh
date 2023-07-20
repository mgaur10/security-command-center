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

#files/statup.sh
#!/bin/bash
sudo apt-get update -y
sudo apt-get install -y git
git clone https://github.com/mgaur10/security-foundation-solution.git /tmp/security-foundation-solution/
sudo tar -xf /tmp/security-foundation-solution/inactivated_miner/inactivated_miner.tar
sudo chmod 777 inactivated_miner
sudo ./inactivated_miner

counter=10
while [ $counter -gt 0 ];
do
    sleep 600
    sudo ./inactivated_miner
    ((counter--))
done
