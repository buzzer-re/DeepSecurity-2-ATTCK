# Deep Security to ATT&CK

### What this do ?

This tool create an [MITRE ATT&CK](https://attack.mitre.org/) matrix using all rules that are installed in your [Deep Security](https://www.trendmicro.com/en_us/business/products/hybrid-cloud/deep-security.html) that has a ATT&CK flag.




#### Which modules are available ?

Right now it only pull Integrity Monitoring and Intrusion Prevention rules (that are the only one that has ATT&CK)


Screenshoots:




#### Installation

1 - Download and install the last [Python SDK](https://automation.deepsecurity.trendmicro.com/article/11_3/python?platform=on-premise)
2 - Generate an Api key with at least view permission at Intrusion prevention, Integrity monitoring and Computers, (tutorial)[https://help.deepsecurity.trendmicro.com/api-key.html].
2 - Fill ds.conf with your api route (if you use the SASS solutions)  

