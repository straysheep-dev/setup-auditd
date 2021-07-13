# setup-auditd.sh
Setup auditd (quickly)

```bash
cd $(mktemp -d)
curl -LfO 'https://raw.githubusercontent.com/straysheep-dev/setup-auditd/main/setup-auditd.sh'
chmod +x setup-auditd.sh
sudo ./setup-auditd.sh
```
To have the most surface coverage and compatability out of the box, see this project's rules file:

<https://github.com/Neo23x0/auditd>

Many of MITRE's ATT&CK Matrix id's have been mapped to rule keys thanks to the work here:

<https://github.com/bfuzzy1/auditd-attack>

Because of this, you can query auditd (and potentially upstream log collectors) for events based on the matrix id's in the rule key

**NOTE: Both of the configuration files highlighted above have the [10-base-config.rules](https://github.com/linux-audit/audit-userspace/blob/master/rules/10-base-config.rules) and [99-finalize.rules](https://github.com/linux-audit/audit-userspace/blob/master/rules/99-finalize.rules) included. Those lines will need commented out before using either file with this setup script.**

I've tried to combine the two in a fork, which has been adjusted to work with this script. It's maintained here:

<https://github.com/straysheep-dev/auditd>

## Rules: 
Most of the [default rule files that ship with auditd](https://github.com/linux-audit/audit-userspace/tree/master/rules) are enabled in this setup.

This script was made knowing the previously mentioned custom rule files above have many of these covered, and asks if you'd like to comment out the non-essential rules which will likely be repeated.

If you don't have your own rules, or even have rules but they aren't an extensive custom policy, you can enable any one of the 30-* rules ([nispom](https://github.com/linux-audit/audit-userspace/blob/master/rules/30-nispom.rules), [ospp](https://github.com/linux-audit/audit-userspace/blob/master/rules/30-ospp-v42.rules), [pci](https://github.com/linux-audit/audit-userspace/blob/master/rules/30-pci-dss-v31.rules), [stig](https://github.com/linux-audit/audit-userspace/blob/master/rules/30-stig.rules)) as a base to meet your requirements and have the remaining default rules enabled as well.

This is noisy to watch live, so as always working broad to narrow in scope with this amount of data is an ideal approach

To add your own rules, the [expected method](https://github.com/linux-audit/audit-userspace/blob/master/rules/40-local.rules) is to place them all in file(s) named "40-your-filename.rules"
 
For example, "40-custom-1.rules", "40-custom-2.rules", "40-workstation.rules" etc.

Rules are still interpretted and work fine if you don't follow this method, but this script expects all local or custom rules to follow this naming convention.

## Query Examples:

* Show all commands run with sudo (and their command line switches) since yesterday, in order of time:
```bash
sudo ausearch -ts yesterday -i -k T1548.003_Sudo_and_Sudo_Caching -l | grep 'proctitle='
```
* Same as above, but printing a sorted list of all unique commands (with command line switches, no duplicates, and not by time):
```bash
sudo ausearch -ts yesterday -i -k T1548.003_Sudo_and_Sudo_Caching -l | grep 'proctitle=' | sed 's/ proctitle=/\nproctitle=/g' | grep 'proctitle=' | sort -u
```
* Print a list of all successful logins by date/time, user, and source ip in the last week:
```bash
sudo aureport -ts week-ago -i -l --success
```
* List each rule key and the number of log entries per rule key for the current day:
```bash
sudo aureport -ts today -k --summary
```

## Resources:
For complete and downloadable spreadsheets of the matrix id's, see 'ATT&CK in Excel' click 'Learn more'

<https://attack.mitre.org/resources/working-with-attack/>

Enterprise attack techniques & id's:

<https://attack.mitre.org/techniques/enterprise/>

Enterprise attack mitigations:

<https://attack.mitre.org/mitigations/enterprise/>

Auditd homepage and github:

<https://people.redhat.com/sgrubb/audit/>

<https://github.com/linux-audit/audit-userspace>

## To do:

- [ ] Test on RHEL/SUSE/Arch

- [x] Include buffer size as a prompt option?

- [ ] Include failure mode as a prompt option?

- [ ] Include configuring shipping logs on the network as a prompt option?

- [x] Include options for the different 30-* rulesets:
 * 30-nispom.rules.gz
 * 30-ospp-v42.rules.gz
 * 30-pci-dss-v31.rules.gz
 * 30-stig.rules.gz

- [x] fix issue with the ospp rules in recent versions of auditd
 * ospp rule needs to point to [this](https://github.com/linux-audit/audit-userspace/blob/master/rules/30-ospp-v42.rules) file alone
