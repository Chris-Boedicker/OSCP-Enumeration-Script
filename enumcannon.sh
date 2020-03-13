#!/bin/bash
#by Christopher Boedicker

RED='\033[0;31m'
WHITE='\033[0;97m'
GREEN='\033[0;32m'
NC='\033[0m'

SECONDS=0

usage(){
echo -e ""
echo -e "${RED}Usage: $0 <TARGET-IP> <TYPE>"
echo -e "${WHITE}"
echo -e "Scan Types:"
echo -e "\tFast: Shows all open ports quickly (~15 seconds)"
echo -e "\tFull:	Runs a Fast Scan, then runs a more thorough scan on found ports (~5 minutes)"
echo -e "\tSerious:	Runs a full range port scan, then runs a thorough scan on new ports (~5-10 minutes)"
echo -e "\tUDP:	Runs \"Full\" on UDP ports (~5 minutes)"
echo -e "\tVulners:	Runs CVE scan and nmap Vulns scan on all found ports (~5-15 minutes)"
echo -e "\tRecon:	Suggests recon commands, then prompts to automatically run them"
echo -e "\tComplete:	Runs all the scans (~20-30 minutes)"
echo -e ""
exit 1
}

header(){
echo -e ""

if [ "$2" == "Complete" ]; then
	echo -e "${WHITE}Running all scans on $1"
else
	echo -e "${WHITE}Running a $2 scan on $1"
fi

subnet=$(echo "$1" | cut -d "." -f 1,2,3)".0"

Ping=$(Ping "$1")
nmapCmd="nmap -Pn"

:'
#nmapCmd='echo "${Ping}" | head -n 1'

if ["$nmapCmd" != "nmap"]; then
echo -e "${NC}"
	echo -e "${WHITE}No ping detected.. Running with -Pn option!"
	echo -e "${NC}"
fi
'
ttl=$(echo "${Ping}" | tail -n 1)
if [[  $(echo "${ttl}") != "nmap -Pn" ]]; then
	osType="$(checkOS "$ttl")"	
	echo -e "${NC}"
	echo -e "${LIGHT GREEN}Host is Most likely running $osType"
	echo -e "${NC}"
fi

echo -e ""
echo -e ""
}

assignedPorts(){
if [ -f nmap/Fast_"$1".nmap ]; then
	basicPorts=$(cat nmap/Fast_"$1".nmap | grep open | cut -d " " -f 1 | cut -d "/" -f 1 | tr "\n" "," | cut -c3- | head -c-2)
fi

if [ -f nmap/UDP_"$1".nmap ]; then
	udpPorts=$(cat nmap/UDP_"$1".nmap | grep -w "open " | cut -d " " -f 1 | cut -d "/" -f 1 | tr "\n" "," | cut -c3- | head -c-2)
	if [[ "$udpPorts" == "Al" ]]; then
		udpPorts=""
	fi
fi
}

checkPing(){
pingTest=$(ping -c 1 -W 3 "$1" | grep ttl)
if [[ -z $pingTest ]]; then
        echo "nmap -Pn"
else
        echo "nmap"
	      ttl=$(echo "${pingTest}" | cut -d " " -f 6 | cut -d "=" -f 2)
	echo "${ttl}"
fi
}

checkOS(){
if [ "$1" == 256 ] || [ "$1" == 255 ] || [ "$1" == 254 ]; then
        echo "OpenBSD/Cisco/Oracle"
elif [ "$1" == 128 ] || [ "$1" == 127 ]; then
        echo "Windows"
elif [ "$1" == 64 ] || [ "$1" == 63 ]; then
        echo "Linux"
else
        echo "Unknown OS!"
fi
}

cmpPorts(){
oldIFS=$IFS
IFS=','
touch nmap/cmpPorts_"$1".txt

for i in $(echo "${allPorts}")
do
	if [[ "$i" =~ ^($(echo "${basicPorts}" | sed 's/,/\|/g'))$ ]]; then
       	       :
       	else
       	        echo -n "$i," >> nmap/cmpPorts_"$1".txt
       	fi
done

extraPorts=$(cat nmap/cmpPorts_"$1".txt | tr "\n" "," | head -c-1)
rm nmap/cmpPorts_"$1".txt
IFS=$oldIFS
}

fastScan(){
echo -e "${GREEN}---------------------Starting Nmap Fast Scan---------------------"
echo -e "${NC}"

$nmapCmd -T4 --max-retries 1 --max-scan-delay 20 --defeat-rst-ratelimit --open -oN nmap/Fast_"$1".nmap "$1"
assignedPorts "$1"

echo -e ""
echo -e ""
echo -e ""
}

fullScan(){
echo -e "${GREEN}---------------------Starting Nmap Full Scan---------------------"
echo -e "${NC}"

if [ -z $(echo "${basicPorts}") ]; then
        echo -e "${WHITE} No ports in fast scan.. Skipping!"
else
	$nmapCmd -A -p$(echo "${basicPorts}") -oN nmap/Full_"$1".nmap "$1" 
fi

if [ -f nmap/Full_"$1".nmap ] && [[ ! -z $(cat nmap/Full_"$1".nmap | grep -w "Service Info: OS:") ]]; then
	serviceOS=$(cat nmap/Full_"$1".nmap | grep -w "Service Info: OS:" | cut -d ":" -f 3 | cut -c2- | cut -d ";" -f 1 | head -c-1)
	if [[ "$osType" != "$serviceOS"  ]]; then
		osType=$(echo "${serviceOS}")
		echo -e "${NC}"
		echo -e "${NC}"
		echo -e "${GREEN}OS Detection modified to: $osType"
		echo -e "${NC}"
	fi
fi

echo -e ""
echo -e ""
echo -e ""
}

UDPScan(){
echo -e "${GREEN}----------------------Starting Nmap UDP Scan----------------------"
echo -e "${NC}"

$nmapCmd -sU --max-retries 1 --open -oN nmap/UDP_"$1".nmap "$1"
assignedPorts "$1"

if [ ! -z $(echo "${udpPorts}") ]; then
        echo ""
        echo ""
        echo -e "${WHITE}Making a script scan on UDP ports: $(echo "${udpPorts}" | sed 's/,/, /g')"
        echo -e "${NC}"
	if [ -f /usr/share/nmap/scripts/vulners.nse ]; then
        	$nmapCmd -sC -sV -sU --script vulners --script-args mincvss=7.0 -p$(echo "${udpPorts}") -oN nmap/UDP_"$1".nmap "$1"
	else
        	$nmapCmd -sC -sV -sU -p$(echo "${udpPorts}") -oN nmap/UDP_"$1".nmap "$1"
	fi
fi

echo -e ""
echo -e ""
echo -e ""
}

seriousScan(){
echo -e "${GREEN}---------------------Starting Nmap Serious Scan----------------------"
echo -e "${NC}"

$nmapCmd -p- --max-retries 1 --max-rate 500 --max-scan-delay 20 -T4 -v -oN nmap/Serious_"$1".nmap "$1"
assignedPorts "$1"

if [ -z $(echo "${basicPorts}") ]; then
	echo ""
        echo ""
        echo -e "${WHITE}Making a script scan on all ports"
        echo -e "${NC}"
        $nmapCmd -sC -sV -p$(echo "${allPorts}") -oN nmap/Serious_"$1".nmap "$1"
	assignedPorts "$1"
else
	cmpPorts "$1"
	if [ -z $(echo "${extraPorts}") ]; then
        	echo ""
        	echo ""
		allPorts=""
        	echo -e "${WHITE}No new ports"
		rm nmap/Serious_"$1".nmap
        	echo -e "${NC}"
	else
		echo ""
        	echo ""
        	echo -e "${WHITE}Making a script scan on extra ports: $(echo "${extraPorts}" | sed 's/,/, /g')"
        	echo -e "${NC}"
        	$nmapCmd -sC -sV -p$(echo "${extraPorts}") -oN nmap/Serious_"$1".nmap "$1"
		assignedPorts "$1"
	fi
fi

echo -e ""
echo -e ""
echo -e ""
}

vulnerScan(){
echo -e "${GREEN}---------------------Starting Nmap Vulnerable Scan---------------------"
echo -e "${NC}"

if [ -z $(echo "${allPorts}") ]; then
	portType="basic"
	ports=$(echo "${basicPorts}")
else
	portType="all"
	ports=$(echo "${allPorts}")
fi


if [ ! -f /usr/share/nmap/scripts/vulners.nse ]; then
	echo -e "${RED}Please install 'vulners.nse' nmap script:"
	echo -e "${RED}https://github.com/vulnersCom/nmap-vulners"
        echo -e "${RED}"
        echo -e "${RED}Skipping CVE scan!"
	echo -e "${NC}"
else    
	echo -e "${WHITE}Running CVE scan on $portType ports"
	echo -e "${NC}"
	$nmapType -sV --script vulners --script-args mincvss=7.0 -p$(echo "${ports}") -oN nmap/CVEs_"$1".nmap "$1"
	echo ""
fi

echo ""
echo -e "${WHITE}Running Vuln scan on $portType ports"
echo -e "${NC}"
$nmapCmd -sV --script vuln -p$(echo "${ports}") -oN nmap/Vulners_"$1".nmap "$1"
echo -e ""
echo -e ""
echo -e ""
}

recon(){

reconRecommend "$1" | tee nmap/Recon_"$1".nmap

availableRecon=$(cat nmap/Recon_"$1".nmap | grep "$1" | cut -d " " -f 1 | sed 's/.\///g; s/.py//g; s/cd/odat/g;' | sort -u | tr "\n" "," | sed 's/,/,\ /g' | head -c-2)

secs=30
count=0

reconCommand=""

if [ ! -z "$availableRecon"  ]; then
	while [ ! $(echo "${reconCommand}") == "!" ]; do
		echo -e "${WHITE}"
		echo -e "Which commands would you like to run?${NC}\nComplete (Default), $availableRecon, Skip <!>\n"
		while [[ ${count} -lt ${secs} ]]; do
			tlimit=$(( $secs - $count ))
			echo -e "\rRunning Default in (${tlimit}) s: \c"
			read -t 1 reconCommand
			[ ! -z "$reconCommand" ] && { break ;  }
			count=$((count+1))
		done
		if [ "$reconCommand" == "Complete" ] || [ -z $(echo "${reconCommand}") ]; then
			runRecon "$1" "Complete"
			reconCommand="!"
		elif [[ "$reconCommand" =~ ^($(echo "${availableRecon}" | tr ", " "|"))$ ]]; then
			runRecon "$1" $reconCommand
			reconCommand="!"
		elif [ "$reconCommand" == "Skip" ] || [ "$reconCommand" == "!" ]; then
			reconCommand="!"
			echo -e ""
			echo -e ""
			echo -e ""
		else
			echo -e "${NC}"
			echo -e "${RED}Incorrect choice!"
			echo -e "${NC}"
		fi
	done
fi

}

reconRecommend(){
echo -e "${GREEN}---------------------Recon Recommendations----------------------"
echo -e "${NC}"

oldIFS=$IFS
IFS=$'\n'

######## if [ ]


if [ -f nmap/Serious_"$1".nmap ] && [ -f nmap/Full_"$1".nmap ]; then
	ports=$(echo "${allPorts}")
	file=$(cat nmap/Full_"$1".nmap nmap/Serious_"$1".nmap | grep -w "open")
elif [ -f nmap/Serious_"$1".nmap ]; then
	ports=$(echo "${allPorts}")
	file=$(cat nmap/Fast_"$1".nmap nmap/Serious_"$1".nmap | grep -w "open")
elif [ -f nmap/Full_"$1".nmap ]; then
	ports=$(echo "${basicPorts}")
	file=$(cat nmap/Full_"$1".nmap | grep -w "open")
else
	ports=$(echo "${basicPorts}")
	file=$(cat nmap/Fast_"$1".nmap | grep -w "open")

fi

if [[ ! -z $(echo "${file}" | grep -i http) ]]; then
	echo -e "${NC}"
	echo -e "${WHITE}Web Servers Recon:"
	echo -e "${NC}"
fi

for line in $file; do
	if [[ ! -z $(echo "${line}" | grep -i http) ]]; then
		port=$(echo "${line}" | cut -d "/" -f 1)
		if [[ ! -z $(echo "${line}" | grep -w "IIS") ]]; then
			pages=".html,.asp,.php"
		else
			pages=".html,.php"
		fi
		if [[ ! -z $(echo "${line}" | grep ssl/http) ]]; then
			#echo "sslyze --regular $1 | tee recon/sslyze_$1_$port.txt"
			echo "sslscan $1 | tee recon/sslscan_$1_$port.txt"
			echo "gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x $pages -u https://$1:$port -o recon/gobuster_$1_$port.txt"
			echo "nikto -host https://$1:$port -ssl | tee recon/nikto_$1_$port.txt"
		else
			echo "gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x $pages -u http://$1:$port -o recon/gobuster_$1_$port.txt"
			echo "nikto -host $1:$port | tee recon/nikto_$1_$port.txt"
		fi
		echo ""
	fi
done

if [ -f nmap/Serious_"$1".nmap ]; then
	cms=$(cat nmap/Serious_"$1".nmap | grep http-generator | cut -d " " -f 2)
	if [ ! -z $(echo "${cms}") ]; then
		for line in $cms; do
			port=$(cat nmap/Serious_"$1".nmap | grep "$line" -B1 | grep -w "open" | cut -d "/" -f 1)
			if [[ "$cms" =~ ^(Joomla|WordPress|Drupal)$ ]]; then
				echo -e "${NC}"
				echo -e "${WHITE}CMS Recon:"
				echo -e "${NC}"
			fi
			case "$cms" in
				Joomla!) echo "joomscan --url $1:$port | tee recon/joomscan_$1_$port.txt";;
				WordPress) echo "wpscan --url $1:$port --enumerate p | tee recon/wpscan_$1_$port.txt";;
				Drupal) echo "droopescan scan drupal -u $1:$port | tee recon/droopescan_$1_$port.txt";;
			esac
		done
	fi
fi

if [[ ! -z $(echo "${file}" | grep -w "445/tcp") ]]; then
	echo -e "${NC}"
	echo -e "${WHITE}SMB Recon:"
	echo -e "${NC}"
	echo "smbmap -H $1 | tee recon/smbmap_$1.txt"
	echo "smbclient -L \"//$1/\" -U \"guest\"% | tee recon/smbclient_$1.txt"
	if [[ $osType == "Windows" ]]; then
		echo "nmap -Pn -p445 --script vuln -oN recon/SMB_vulns_$1.txt $1"
  fi
	if [[ $osType == "Linux" ]]; then
		echo "enum4linux -a $1 | tee recon/enum4linux_$1.txt"
	fi
	echo ""
elif [[ ! -z $(echo "${file}" | grep -w "139/tcp") ]] && [[ $osType == "Linux" ]]; then
	echo -e "${NC}"
	echo -e "${WHITE}SMB Recon:"
	echo -e "${NC}"
	echo "enum4linux -a $1 | tee recon/enum4linux_$1.txt"
	echo ""
fi


if [ -f nmap/UDP_"$1".nmap ] && [[ ! -z $(cat nmap/UDP_"$1".nmap | grep open | grep -w "161/udp") ]]; then
	echo -e "${NC}"
	echo -e "${WHITE}SNMP Recon:"
	echo -e "${NC}"
	echo "snmp-check $1 -c public | tee recon/snmpcheck_$1.txt"
	echo "snmpwalk -Os -c public -v $1 | tee recon/snmpwalk_$1.txt"
	echo ""
fi

if [[ ! -z $(echo "${file}" | grep -w "53/tcp") ]]; then
	echo -e "${NC}"
	echo -e "${WHITE}DNS Recon:"
	echo -e "${NC}"
	echo "host -l $1 $1 | tee recon/hostname_$1.txt"
	echo "dnsrecon -r $subnet/24 -n $1 | tee recon/dnsrecon_$1.txt"
	echo "dnsrecon -r 127.0.0.0/24 -n $1 | tee recon/dnsrecon-local_$1.txt"
	echo "dig -x $1 @$1 | tee recon/dig_$1.txt"
	echo ""
fi

if [[ ! -z $(echo "${file}" | grep -w "389/tcp") ]]; then
        echo -e "${NC}"
        echo -e "${WHITE}ldap Recon:"
        echo -e "${NC}"
        echo "ldapsearch -x -h $1 -s base | tee recon/ldapsearch_$1.txt"
        echo "ldapsearch -x -h $1 -b \$(cat recon/ldapsearch_$1.txt | grep rootDomainNamingContext | cut -d ' ' -f2) | tee recon/ldapsearch_DC_$1.txt"
        echo "nmap -Pn -p 389 --script ldap-search --script-args 'ldap.username=\"\$(cat recon/ldapsearch_$1.txt | grep rootDomainNamingContext | cut -d \\" \\" -f2)\"' $1 -oN recon/nmap_ldap_$1.txt"
	echo ""
fi

if [[ ! -z $(echo "${file}" | grep -w "1521/tcp") ]]; then
	echo -e "${NC}"
	echo -e "${WHITE}Oracle Recon \"Exc. from Default\":"
	echo -e "${NC}"
	echo "cd /opt/odat/;#$1;"
	echo "./odat.py sidguesser -s $1 -p 1521"
	echo "./odat.py passwordguesser -s $1 -p 1521 -d XE --accounts-file accounts/accounts-multiple.txt"
	echo "cd -;#$1;"
	echo ""

IFS=$oldIFS

echo -e ""
echo -e ""
echo -e ""
}


runRecon(){
echo -e ""
echo -e ""
echo -e ""
echo -e "${GREEN}---------------------Running Recon Commands----------------------"
echo -e "${NC}"

oldIFS=$IFS
IFS=$'\n'

if [[ ! -d recon/ ]]; then
        mkdir recon/
fi

if [ "$2" == "Complete" ]; then
	reconCommands=$(cat nmap/Recon_"$1".nmap | grep "$1" | grep -v odat)
else
	reconCommands=$(cat nmap/Recon_"$1".nmap | grep "$1" | grep "$2")
fi

for line in $(echo "${reconCommands}"); do
	currentScan=$(echo "$line" | cut -d " " -f 1 | sed 's/.\///g; s/.py//g; s/cd/odat/g;' | sort -u | tr "\n" "," | sed 's/,/,\ /g' | head -c-2)
	fileName=$(echo "${line}" | awk -F "recon/" '{print $2}' | head -c-1)
	if [ ! -z recon/$(echo "${fileName}") ] && [ ! -f recon/$(echo "${fileName}") ]; then
		echo -e "${NC}"
		echo -e "${WHITE}Starting $currentScan scan"
		echo -e "${NC}"
		echo "$line" | /bin/bash
		echo -e "${NC}"
		echo -e "${WHITE}Finished $currentScan scan"
		echo -e "${NC}"
		echo -e "${WHITE}========================="
	fi
done

IFS=$oldIFS

echo -e ""
echo -e ""
echo -e ""
}

footer(){

echo -e "${GREEN}---------------------Completed all Nmap scans---------------------"
echo -e "${NC}"
echo -e ""

if (( $SECONDS > 3600 )) ; then
    let "hours=SECONDS/3600"
    let "minutes=(SECONDS%3600)/60"
    let "seconds=(SECONDS%3600)%60"
    echo -e "${WHITE}Completed in $hours hour(s), $minutes minute(s) and $seconds second(s)" 
elif (( $SECONDS > 60 )) ; then
    let "minutes=(SECONDS%3600)/60"
    let "seconds=(SECONDS%3600)%60"
    echo -e "${WHITE}Completed in $minutes minute(s) and $seconds second(s)"
else
    echo -e "${WHITE}Completed in $SECONDS seconds"
fi
echo -e ""
}

if (( "$#" != 2 )); then
	usage
fi

if [[ $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	:
else
	echo -e "${RED}"
	echo -e "${RED}Invalid IP!"
	echo -e "${RED}"
	usage
fi

if [[ "$2" =~ ^(Fast|Full|UDP|Serious|Vulners|Recon|Complete|fast|full|udp|serious|vulners|recon|complete)$ ]]; then
	if [[ ! -d $1 ]]; then
	        mkdir "$1"
	fi

	cd "$1" || exit
	
	if [[ ! -d nmap/ ]]; then
	        mkdir nmap/
	fi
	
	assignedPorts "$1"

	header "$1" "$2"

  case "$2" in
		Fast | fast) 	fastScan "$1";;
		Full | full)	if [ ! -f nmap/Fast_"$1".nmap ]; then fastScan "$1"; fi
				fullScan "$1";;
		UDP | udp) 	UDPScan "$1";;
		Serious| serious) 	seriousScan "$1";;
		Vulners | vulners) 	if [ ! -f nmap/Fast_"$1".nmap ]; then fastScan "$1"; fi
				vulnersScan "$1";;
		Recon | recon) 	if [ ! -f nmap/Fast_"$1".nmap ]; then fastScan "$1"; fi
				if [ ! -f nmap/Full_"$1".nmap ]; then fullScan "$1"; fi
				recon "$1";;
		Complete | complete)	fastScan "$1"
				fullScan "$1"
				UDPScan "$1"
				seriousScan "$1"
				vulnersScan "$1"
				recon "$1";;
	esac

	footer
else
	echo -e "${RED}"
	echo -e "${RED}Invalid Type!"
	echo -e "${RED}"
	usage 
fi
