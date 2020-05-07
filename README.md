# Deep Security to ATT&CK

### What this do ?

This tool create an [MITRE ATT&CK](https://attack.mitre.org/) matrix using all rules that are installed in your [Deep Security](https://www.trendmicro.com/en_us/business/products/hybrid-cloud/deep-security.html) that has a ATT&CK flag.




#### Which modules are available ?

Right now it only pull Integrity Monitoring and Intrusion Prevention rules (that are the only one that has ATT&CK)


#### Screenshoot (DSaaS):


![Deep Security SaSS](/screenshoots/dsass.png "Deep Security SaaS")

#### Installation

* Download and install the last [Python SDK](https://automation.deepsecurity.trendmicro.com/article/11_3/python?platform=on-premise)
* Generate an Api key with at least view permission at Intrusion prevention, Integrity monitoring and Computers, [tutorial](https://help.deepsecurity.trendmicro.com/api-key.html).
* Fill ds.conf with your api route and key


### Usage

Just:
  ```python 
    python dsattck.py
  ```
If you filled the config file correctly, everything should work! This will generate 2 json files, enviroment and applied rules, an matrix with ALL rules and a matrix with the applied rules only, you can submit this files at [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/enterprise/)



Please contact about any bug that you may found, the API/SDK change a LOT!

