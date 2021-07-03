# setup-auditd.sh
Setup auditd (quickly)

Many of MITRE's ATT&CK Matrix id's have been mapped out thanks to the work here:

<https://github.com/bfuzzy1/auditd-attack>

Because of this, you can query auditd for events based on the matrix id's.

EXAMPLES:
* Show all commands run with sudo since yesterday, (in order of execution time):
```bash
sudo ausearch -ts yesterday -i -k T1548.003_2 -l | grep 'proctitle='
```
* Same as above, but printing a sorted list of all unique commands (no duplicates, and not by time):
```bash
sudo ausearch -ts yesterday -i -k T1548.003_2 -l | grep 'proctitle=' | sed 's/ proctitle=/\nproctitle=/g' | grep 'proctitle=' | sort -u
```
## Rules: 
Most of the [default rule files that ship with auditd](https://github.com/linux-audit/audit-userspace/tree/master/rules) are also enabled in this setup.

This is noisy to watch live, so as always working broad to narrow in scope with this amount of data is an ideal approach

For all of the "30-" rules, you can choose during setup between nispom, ospp, pci, or stig.

To add your own rules, the [recommended method](https://github.com/linux-audit/audit-userspace/blob/master/rules/40-local.rules) is to place them all in file(s) named "40-your-filename.rules"
 
For example, "40-custom-1.rules", "40-custom-2.rules", "40-workstation.rules" etc.

Rules are still interpretted and work fine if you don't follow this method, but this script expects all local or custom rules to follow this naming convention.

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

- [x] Include options for the different 30-* rulesets:
 * 30-nispom.rules.gz
 * 30-ospp-v42.rules.gz
 * 30-pci-dss-v31.rules.gz
 * 30-stig.rules.gz

- [ ] fix issue with the ospp rules in recent versions of auditd
