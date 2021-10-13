# setup-auditd.sh
Setup auditd (quickly)

```bash
cd $(mktemp -d)
curl -LfO 'https://raw.githubusercontent.com/straysheep-dev/setup-auditd/main/setup-auditd.sh'
# optionally curl or add custom rule file(s) not part of the built-in samples to the cwd before executing
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

Prompts allow you to enable any one of the 30-* rules ([nispom](https://github.com/linux-audit/audit-userspace/blob/master/rules/30-nispom.rules), [ospp](https://github.com/linux-audit/audit-userspace/blob/master/rules/30-ospp-v42.rules), [pci](https://github.com/linux-audit/audit-userspace/blob/master/rules/30-pci-dss-v31.rules), [stig](https://github.com/linux-audit/audit-userspace/blob/master/rules/30-stig.rules))

Custom rules found in same directory when executing this script, using the naming convention for [local rules](https://github.com/linux-audit/audit-userspace/blob/master/rules/40-local.rules) will be applied.
 
For example, "40-custom-1.rules", "40-custom-2.rules", "40-workstation.rules" etc.

Rules can always be installed later, and are still interpretted without issue if you don't follow this, but this script expects all local or custom rules to follow this naming convention.

## Query Examples:
```bash
# General report
sudo aureport -ts <start-time> --summary

# Key report
sudo aureport -ts <start-time> -k --summary

# Login report
sudo aureport -ts <start-time> -i -l --success

# Searching
sudo ausearch -ts <start-time> -i -l -k <key> | grep 'proctitle='
sudo ausearch -ts <start-time> -i -l -sc <syscall> | grep 'proctitle='
sudo ausearch -ts <start-time> -i -l -x <executable> | grep 'proctitle='

# Unique, by total occurances, greatest to least
sudo ausearch -ts <start-time> -i -l -k <key> | grep 'proctitle=' | sed 's/^.*proctitle=//g' | sort | uniq -c | sort -nr

# Timing
## Start time can be general or precise, lists all events from the specified time until now:
-ts today
-ts yesterday
-ts week-ago
-ts 01/01/2021
-ts 01/01/2021 08:00:00

## End time takes the same arguments, lists all events up until the specified end time:
-te today
-te 12:00:00

## Combine start time and end time for scope
-ts month-ago -te 01/01/2021 08:00:00
-ts 01/01/2021 08:00:00 -te yesterday
-ts 01/01/2021 08:00:00 -te 01/01/2021 18:30:00
```

### Filtering the Noise

Workstations and busy servers can log many thousands of keys.

Test rules / keys over time before pushing them to production.

Identify keys that could be used to flood / overwrite the logs by an adversary.

Work broad to narrow in scope.

```bash
# Search results with timestamps
sudo ausearch -ts <start-time> -i -l -k <key> | grep 'proctitle='
# Search results ordered by occurrances, greatest to least
sudo ausearch -ts <start-time> -i -l -k <key> | grep 'proctitle=' | sed 's/^.*: proctitle=//g' | sort | uniq -c | sort -nr
# Review manually and filter out results which are known good
sudo ausearch -ts <start-time> -i -l -k <key> | grep 'proctitle=' | sed 's/^.*: proctitle=//g' | sort | uniq -c | sort -nr | grep -v 'filter-1' | grep -v 'filter -2' | ...
# Look for specific threats
sudo ausearch -ts <start-time> -i -l -k <key> | grep 'proctitle=' | sed 's/^.*: proctitle=//g' | sort | uniq -c | sort -nr | grep '<binary>'
sudo ausearch -ts <start-time> -i -l -k <key> | grep 'proctitle=' | sed 's/^.*: proctitle=//g' | sort | uniq -c | sort -nr | grep 'curl'
sudo ausearch -ts <start-time> -i -l -k <key> | grep 'proctitle=' | sed 's/^.*: proctitle=//g' | sort | uniq -c | sort -nr | grep 'nc'

# Substitute `proctitle=` for other key / value pairs in an auditd event, such as `name=` `key=` `comm=`
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

Rule Creation:

RHEL 6 Security Guide:
<https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/sec-defining_audit_rules_and_controls>

RHEL 8 Security Guide:
<https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/auditing-the-system_security-hardening#using-auditctl-for-defining-and-executing-audit-rules_auditing-the-system>


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
