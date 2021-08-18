#!/bin/bash

# Thanks & Acknowledgements
# https://github.com/linux-audit		#source
# https://people.redhat.com/sgrubb/audit/	#source
# https://github.com/bfuzzy1/auditd-attack	#rule-mapping
# https://github.com/Neo23x0/auditd		#configuration
# https://attack.mitre.org/			#attack-framework

# Vars

RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success
YELLOW="\033[01;33m"   # Warnings
BLUE="\033[01;34m"     # Information
BOLD="\033[01;01m"     # Highlight
RESET="\033[00m"       # Normal

AUDIT_DOCS=0
AUDITD_CONF=/etc/audit/auditd.conf
AUDIT_RULES_D=/etc/audit/rules.d/
NUM_LOGS=0
LOG_SIZE=0
LOG_FORMAT=0
BUFFER_SIZE=0


# Start

function isRoot() {
	if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
	fi
}
isRoot

function checkCwd() {
	# Needs a better solution
	if  ! [ -e 'setup-auditd.sh' ]; then
		echo "To avoid issues, execute this script from it's current working directory. Quitting."
		echo "If you renamed this script, change this function or rename it 'setup-auditd.sh'"
		exit 1
	fi
}
checkCwd

#function skeletonFunction() {
#	echo ""
#	echo "Your custom prompt goes here."
#	echo ""
#	until [[ $CUSTOM_VAR =~ ^(OPTION1|OPTION2)$ ]]; do
#		read -rp "Custom question: " -e -i OPTION1 CUSTOM_VAR
#	done
#}
#skeletonFunction

function checkOS() {
	# Check OS version
	if [[ -e /etc/debian_version ]]; then
		source /etc/os-release
		OS="${ID}" # debian, kali, or ubuntu
		if [[ -e /etc/debian_version ]]; then
			if [[ ${ID} == "debian" || ${ID} == "raspbian" ]]; then
				if [[ ${VERSION_ID} -ne 10 ]]; then
					echo "Your version of Debian (${VERSION_ID}) is not supported. Please use Debian 10 Buster"
					exit 1
				fi
			fi
		fi
	elif [[ -e /etc/fedora-release ]]; then
		source /etc/os-release
		OS="${ID}"
	elif [[ -e /etc/centos-release ]]; then
		OS=centos
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	else
		echo "Looks like you aren't running this installer on a Debian, Ubuntu, Fedora, CentOS or Arch Linux system"
		exit 1
	fi

	# Temporary solution until more OS's can be tested
	if [[ ${OS} == 'debian' ]] || [[ ${OS} == 'ubuntu' ]] || [[ ${OS} == 'kali' ]]; then
		AUDIT_DOCS=/usr/share/doc/auditd/examples/rules/
	elif [[ ${OS} == 'fedora' ]]; then
		AUDIT_DOCS=/usr/share/audit/sample-rules/
	fi
}
checkOS

function checkPackages() {
	if ! (command -v auditd); then
		echo -e "${BLUE}[>]${RESET}Installing auditd package..."
		sudo apt update
		sudo apt install -y auditd
		#auditd.service is enabled and starts by default
		sleep 2
		if ! (command -v auditd); then
			exit 1
		fi
		echo -e "${BLUE}[✓]${RESET}Done."
	fi
}
checkPackages

function checkServices() {
	if ! [ -e /etc/systemd/system/multi-user.target.wants/auditd.service ]; then
		echo -e "${BLUE}[>]${RESET}Enabling auditd.service..."
		systemctl enable auditd.service
		systemctl restart auditd.service
	fi
}
checkServices

function makeTemp() {
	SETUPAUDITDIR=$(mktemp -d)
	export SETUPAUDITDIR
	if (ls -l | grep -q "40-.*.rules"); then
		cp 40-*.rules "$SETUPAUDITDIR"
	fi
	cd "$SETUPAUDITDIR"
	echo ""
	echo -e "${BLUE}[i]${RESET}Changing working directory to $SETUPAUDITDIR"

}
makeTemp

function checkCurrentRules() {
	# Check for any currently installed rules
	if $(ls "${AUDIT_RULES_D}" | grep -q ".rules"); then
		echo "======================================================================"
		echo -e "${RED}[-]${RESET}Currently installed auditd rule file(s) to remove:"
		echo "$(ls ${AUDIT_RULES_D} | grep '.rules' || echo 'none')"
		echo ""
		echo -e "${GREEN}[+]${RESET}Custom auditd rule file(s) to be installed:"
		echo "$(ls ${SETUPAUDITDIR} | grep '.rules' || echo 'none')"
		echo ""
		until [[ $CONTINUE_SETUP =~ ^(y|n)$ ]]; do
			read -rp "Continue with setup? [y/n]: " CONTINUE_SETUP
		done
		if [[ $CONTINUE_SETUP == "n" ]]; then
			exit 1
		elif [[ $CONTINUE_SETUP == "y" ]]; then
			rm "${AUDIT_RULES_D}"* 2>/dev/null
		fi
	# Reset all other rules
	else
		rm "${AUDIT_RULES_D}"* 2>/dev/null
	fi
}
checkCurrentRules

function setLogFormat() {
	echo "======================================================================"
	echo -e "${BLUE}[i]${RESET}Set the logging ${BOLD}format${RESET}"
	echo -e "${BOLD}RAW${RESET} = Machine-readable"
	echo -e "${BOLD}ENRICHED${RESET} = Human-readable"
	echo ""
	until [[ $LOG_FORMAT =~ (RAW|ENRICHED) ]]; do
		read -rp "log_format = " -e -i ENRICHED LOG_FORMAT
	done
}
setLogFormat

function setLogSize() {
	echo "======================================================================"
	echo -e "${BLUE}[i]${RESET}Set the ${BOLD}file size${RESET} of each log"
	echo -e "${BLUE}[i]${RESET}Recommended setting: ${BOLD}8${RESET} (8MB)"
	echo -e "${BLUE}[i]${RESET}Default setting: ${BOLD}8${RESET} (8MB)"
	echo ""
	until [[ $LOG_SIZE =~ ^[0-9]+$ ]] && [ "$LOG_SIZE" -ge 1 ] && [ "$LOG_SIZE" -le 50 ]; do
		read -rp "max_log_file (MB) = " -e -i 8 LOG_SIZE
	done
}
setLogSize

function setLogNumber() {
	echo "======================================================================"
	echo -e "${BLUE}[i]${RESET}Set the ${BOLD}number of log files${RESET} to maintain locally"
	echo -e "${BLUE}[i]${RESET}Recommended setting if shipping logs: ${BOLD}6+${RESET} (6MB)"
	echo -e "${BLUE}[i]${RESET}Recommended setting if hosting logs: ${BOLD}50+${RESET} 50MB)"
	echo -e "${BLUE}[i]${RESET}Default setting: ${BOLD}8${RESET}"
	echo ""
	until [[ $NUM_LOGS =~ ^[0-9]+$ ]] && [ "$NUM_LOGS" -ge 1 ] && [ "$NUM_LOGS" -le 65535 ]; do
		read -rp "num_logs = " -e -i 8 NUM_LOGS
	done
}
setLogNumber

function setBuffer() {
	echo "======================================================================"
	echo -e "${BLUE}[i]${RESET}Set auditd's ${BOLD}buffer size${RESET}"
	echo -e "${BLUE}[i]${RESET}For busy systems, increase and test this number"
	echo -e "${BLUE}[i]${RESET}Default setting: ${BOLD}8192${RESET}"
	echo ""
	until [[ $BUFFER_SIZE =~ ^[0-9]+$ ]] && [ "$BUFFER_SIZE" -ge 1 ] && [ "$BUFFER_SIZE" -le 65535 ]; do
		read -rp "buffer_size (-b) = " -e -i 8192 BUFFER_SIZE
	done
}
setBuffer

function setSiteRules() {
	echo "======================================================================"
	echo -e "${BLUE}[i]${RESET}Set site-specific rules"
	echo -e "${BOLD}	nispom | ospp | pci | stig | none${RESET}"
	echo -e "If not using custom rules, ${BLUE}stig${RESET} is a good choice"
	echo -e "If custom rules will be installed, choosing ${BLUE}none${RESET} is recommended"
	echo ""
	until [[ $SITE_RULES =~ ^(nispom|ospp|pci|stig|none)$ ]]; do
			read -rp "Enter a choice (lowercase): " -e -i none SITE_RULES
	done
}
setSiteRules

function checkLocalRules() {
	# Check to make sure user's custom/local rules are present if no site rules chosen
	if [[ ${SITE_RULES} == 'none' ]]; then
		if ! (ls | grep -q '40-'); then
			echo ""
			echo -e "${RED}[i]${RESET}No site rules were chosen and no custom rules are present"
			echo -e "${RED}[i]${RESET}Really proceed?"
			
			until [[ $WARNING_CHOICE =~ ^(y|n)$ ]]; do
			read -rp "Continue with setup? [y/n]: " WARNING_CHOICE
			done
			if [[ $WARNING_CHOICE == "n" ]]; then
				exit 1
			fi
		fi
	fi
}
checkLocalRules

function collectAllRules() {
	# Gather all rule files to cwd
	BASE="${AUDIT_DOCS}10-base-config.rules"
	LOGINUID="${AUDIT_DOCS}11-loginuid.rules"
	NO32BIT="${AUDIT_DOCS}21-no32bit.rules"
	LOCAL="$(pwd)/40-*.rules"
	CONTAINER="${AUDIT_DOCS}41-containers.rules"
	INJECT="${AUDIT_DOCS}42-injection.rules"
	KMOD="${AUDIT_DOCS}43-module-load.rules"
	NET="${AUDIT_DOCS}71-networking.rules"
	FIN="${AUDIT_DOCS}99-finalize.rules"

	cp "${BASE}" "${LOGINUID}" "${NO32BIT}" "${CONTAINER}" "${INJECT}" "${KMOD}" "${NET}" "${FIN}" .

	# Site rules need gathered separately, too many ospp rules for one variable?
	if [[ ${SITE_RULES} == 'nispom' ]]; then
		cp "${AUDIT_DOCS}"30-nispom*.rules* .
	elif [[ ${SITE_RULES} == 'pci' ]]; then
		cp "${AUDIT_DOCS}"30-pci*.rules* .
	elif [[ ${SITE_RULES} == 'ospp' ]]; then
		cp "${AUDIT_DOCS}"$(ls "${AUDIT_DOCS}" | grep "30-ospp-v[0-9][0-9].rules*") .
	elif [[ ${SITE_RULES} == 'stig' ]]; then
		cp "${AUDIT_DOCS}"30-stig*.rules* .
	elif [[ ${SITE_RULES} == 'none' ]]; then
		echo "## Site specific rules placeholder file" > 30-site.rules
	fi

	# Gunzip package rules if they're archived
	if [ -e *.rules.gz ]; then
		gunzip *.rules.gz
	fi

	# Use default local rules placeholder if none / no custom rules are present
	if ! (ls | grep -q '40-*.rules'); then
		cp "${AUDIT_DOCS}40-local.rules" .
	fi
}
collectAllRules

function applySettings() {
	# Apply the settings chosen by user during setup
	# /etc/audit/auditd.conf changes:
	if [ -e "${AUDITD_CONF}" ]; then
		echo ""
		grep -q -x "log_format = ${LOG_FORMAT}" "${AUDITD_CONF}" || (sed -i 's/^log_format = .*$/log_format = '"${LOG_FORMAT}"'/' "${AUDITD_CONF}")
		grep -q -x "num_logs = ${NUM_LOGS}" "${AUDITD_CONF}" || (sed -i 's/^num_logs = .*$/num_logs = '"${NUM_LOGS}"'/' "${AUDITD_CONF}")
		grep -q -x "max_log_file = ${LOG_SIZE}" "${AUDITD_CONF}" || (sed -i 's/^max_log_file = .*$/max_log_file = '"${LOG_SIZE}"'/' "${AUDITD_CONF}")
	else
		echo -e "${RED}"'[!]'"Missing auditd.conf file.${RESET}"
		exit 1
	fi
	# Next, set the buffer size in 10-base-config.rules, if this file is missing we'll see below
	if [ -e 10-base-config.rules ]; then
		sed -i 's/^-b.*$/-b '"${BUFFER_SIZE}"'/' 10-base-config.rules
	fi
}
applySettings

function adjustRules() {
	# Make any adjustments to the built in rule files from /usr/share/**rules here
	# This will need a better solution going forward

	# Offer to comment out non-essential built in rules if using a local/custom rules file
	if [[ ${SITE_RULES} == 'none' ]]; then
		echo "To avoid overlap with custom rules, would you like"
		echo "comment out the non-essential built in rules?"
		echo ""
		until [[ $COMMENT_BUILTINS =~ ^(y|n)$ ]]; do
			read -rp "[y/n]?: " -e -i y COMMENT_BUILTINS
		done
	fi
	if [[ $COMMENT_BUILTINS == 'y' ]]; then
		sed -i 's/^-a/#-a/' "21-no32bit.rules"
		sed -i 's/^-a/#-a/' "42-injection.rules"
		sed -i 's/^-a/#-a/' "43-module-load.rules"
		sed -i 's/^-a/#-a/' "71-networking.rules"
	fi
}
adjustRules

function setAuditing() {
	# Putting everything together

	# Set rules to be immutable
	sed -i 's/#-e 2/-e 2/' "99-finalize.rules"

	# Remove placeholder policy file
	if [ -e "${AUDIT_RULES_D}"audit.rules ]; then
		rm "${AUDIT_RULES_D}"audit.rules
	fi

	RULES[0]="10-base-config.rules"
	RULES[1]="11-loginuid.rules"
	RULES[2]="21-no32bit.rules"
	RULES[3]="30-*.rules"
	RULES[4]="40-*.rules"
	RULES[5]="41-containers.rules"
	RULES[6]="42-injection.rules"
	RULES[7]="43-module-load.rules"
	RULES[8]="71-networking.rules"
	RULES[9]="99-finalize.rules"

	for RULE in ${RULES[@]}; do
		if [[ -e "${RULE}" ]]; then
			chmod 440 "${RULE}" && cp "${RULE}" -t "${AUDIT_RULES_D}" 2>/dev/null && rm "${RULE}" && echo -e "${GREEN}[+]${RESET}${BOLD}Installing ${RULE}${RESET}"
		else
			echo -e "${RED}"'[!]'"Missing ${RULE}, and cannot locate rule file to install.${RESET}"
		fi
	done

	# Cleanup
	cd /tmp && \
	rm -rf $SETUPAUDITDIR

	# Check for any errors
	echo ""
	echo -e "${GREEN}[i]${RESET}Running augenrules --check"
	augenrules --check 2>&1
	echo -e "${GREEN}[i]${RESET}Running augenrules --load to update rules"
	augenrules --load 2>&1
	echo "======================================================================"
	echo -e "${BLUE}[^]${RESET}Review the line numbers called out in /etc/audit/audit.rules"
	echo -e "${BLUE}[^]${RESET}Tune installed rules directly in /etc/audit/rules.d/*"

	echo ""
	echo -e "${BLUE}[>]${RESET}${BOLD}Log format = ${LOG_FORMAT}${RESET}"
	echo -e "${BLUE}[>]${RESET}${BOLD}Log file size = ${LOG_SIZE}MB${RESET}"
	echo -e "${BLUE}[>]${RESET}${BOLD}Number of logs = ${NUM_LOGS}${RESET}"
	echo -e "${BLUE}[>]${RESET}${BOLD}Buffer size = ${BUFFER_SIZE}${RESET}"
	echo ""
	echo -e "${BLUE}[✓]${RESET}Done. Reminder: auditd rules aren't locked until ${BOLD}after${RESET} next reboot."
}
setAuditing
