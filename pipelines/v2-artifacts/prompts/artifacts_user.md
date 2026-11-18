Turn what you have established into detection and response code for the cell. Read soc_get_log_schema first: it gives the exact data object your code receives, the entry-function contract and the allowed imports.

Produce and submit, with soc_submit_artifact:

1. A set of Sigma rules (kind sigma_rule, one rule per submission, up to five) that detect the intrusion's behaviors in these logs without firing on the authorized activity: the foreign VPN logon, the service-account spray, the command-and-control beacons, the exfiltration, the persistence and the lateral movement. Tag each with ATT&CK ids.
2. One hunt script (kind hunt_script) defining hunt(data) that flags every malicious record across all four log sources and nothing benign, with the behavior and host on each finding.
3. One IOC extractor (kind ioc_extractor) defining extract(data) that returns the intrusion's indicators from the logs: domains, ips, url paths, files, the scheduled task and service names, the accounts.

Before submitting, test each script with lab_run_script and each rule with lab_test_rule, read what they match, and fix what the lab shows. A rejected submission tells you why; fix it and resubmit under the same name. Up to eight artifacts are accepted in all. Nothing is executed by the SOC; your code is tested later in an isolated offline container.
