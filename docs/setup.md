# Lab setup

Everything here runs on machines and accounts you own. Never point Atomic Red Team at a
work laptop or a shared AWS account.

Rough cost: free, apart from disk space. The AWS part stays inside the free tier if you
delete the trail when you're done.

## 1. Windows victim VM

1. Install a free hypervisor: **UTM** (Apple Silicon Mac), VirtualBox or VMware Workstation Player.
2. Download the free **Windows 11 evaluation** ISO from Microsoft and create a VM
   (4 GB RAM, 60 GB disk is enough).
3. Take a snapshot named `clean` before installing anything else. You'll roll back to it
   after each attack run.

## 2. Sysmon

Sysmon writes the detailed process, network and memory-access events the Windows rules use.

```powershell
# In an admin PowerShell on the VM
Invoke-WebRequest https://download.sysinternals.com/files/Sysmon.zip -OutFile Sysmon.zip
Expand-Archive Sysmon.zip
Invoke-WebRequest https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile sysmon.xml
.\Sysmon\Sysmon64.exe -accepteula -i sysmon.xml
```

Check it works: **Event Viewer → Applications and Services Logs → Microsoft → Windows →
Sysmon → Operational** should fill with events.

The SwiftOnSecurity config does **not** log every LSASS access (Event ID 10) by default.
To test the LSASS rule, add a `ProcessAccess` include for `TargetImage` ending in
`lsass.exe` and reload with `Sysmon64.exe -c sysmon.xml`.

## 3. SIEM (pick one)

**Splunk Free** (simplest):
1. Install Splunk Enterprise on your Mac or a second VM and switch the license to Free.
2. Install the Splunk Universal Forwarder on the Windows VM.
3. In the forwarder's `inputs.conf`, collect
   `WinEventLog://Microsoft-Windows-Sysmon/Operational` and `WinEventLog://Security`,
   both with `renderXml = false`.
4. Install the **Splunk Add-on for Sysmon** so fields like `Image` and `CommandLine` are extracted.

**Elastic** (if you'd rather): run Elasticsearch and Kibana with Docker, then install
**Elastic Agent** on the VM with the Windows integration and Sysmon channel enabled.

Convert a rule to your SIEM's query language with `sigma-cli`:

```bash
pip install sigma-cli
sigma plugin install splunk        # or: elasticsearch
sigma plugin install sysmon        # maps the rules onto Sysmon event IDs
sigma convert -t splunk -p sysmon rules/windows/win_office_spawns_shell.yml
```

That prints a Splunk search you can save as an alert:

```
EventID=1 ParentImage IN ("*\\winword.exe", "*\\excel.exe", ...) Image IN ("*\\cmd.exe", "*\\powershell.exe", ...)
```

## 4. Attack simulation: Atomic Red Team

```powershell
# On the VM, in an admin PowerShell. Turn off Defender real-time protection first,
# or it will block several tests (and that block is itself worth noting).
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics

Invoke-AtomicTest T1059.001 -ShowDetailsBrief   # see what a test will do first
Invoke-AtomicTest T1059.001 -TestNumbers 1
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup
```

| Rule | Atomic tests to try |
| --- | --- |
| Office spawns shell | T1204.002 (needs Office installed) |
| PowerShell encoded command | T1059.001 |
| LSASS memory access | T1003.001 |
| Suspicious scheduled task | T1053.005 |
| Account lockout | T1110.001 (set an account lockout policy first: `net accounts /lockoutthreshold:5`) |
| Security log cleared | T1070.001 |

Restore the `clean` snapshot when you're done.

## 5. AWS CloudTrail sandbox

1. Use a **separate** AWS account (a free-tier account or an AWS Organizations sandbox), not
   one with anything real in it. Turn on MFA for the root user.
2. CloudTrail → **Create trail**, logging management events to a new S3 bucket.
3. Simulate the attacks with the AWS CLI as a test IAM user:

```bash
# T1098: attach AdministratorAccess to a throwaway user
aws iam create-user --user-name lab-backdoor
aws iam attach-user-policy --user-name lab-backdoor \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# T1562.008: stop the trail (start it again right after)
aws cloudtrail stop-logging --name <your-trail>
aws cloudtrail start-logging --name <your-trail>

# T1098: give the user a console password (and T1078.004: sign in with it, no MFA)
aws iam create-login-profile --user-name lab-backdoor --password '<a strong temporary password>'
# Now sign in at https://<account-id>.signin.aws.amazon.com/console as lab-backdoor

# Clean up
aws iam delete-login-profile --user-name lab-backdoor
aws iam detach-user-policy --user-name lab-backdoor \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws iam delete-user --user-name lab-backdoor
```

4. CloudTrail delivers files to S3 within about 15 minutes. Download one and replay it:

```bash
gunzip 111122223333_CloudTrail_us-east-1_*.json.gz
python -m detectionlab.scan 111122223333_CloudTrail_us-east-1_*.json --rules rules/aws
```

5. Delete the trail and bucket when you're finished to stay in the free tier.

## 6. Record what happened

For every test run, fill in the **Lab results** table in the README: did the rule fire,
how long until the alert showed up, and what normal activity also matched. The misses and
false positives are the most valuable part, so write those down too.
