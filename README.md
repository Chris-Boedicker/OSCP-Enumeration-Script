enumcannon

A script that you can run in the background!
Summary

I have created this script as I was preparing for my first attempt OSCP exam when I was tasked by my mentor toe automate the enumation process.

This will ensure two things:
1) Automate nmap scans. 2) Always have some recon running in the background.

Once you find the inital ports in around 10 seconds, you then can start manually looking into those ports, and let the rest run in the background with no interaction from your side whatsoever.
Features:

    Fast:	Shows all open ports quickly (~15 seconds)
    Full:	Runs Quick Scan, then runs a more thorough scan on found ports (~5 minutes)
    Serious: Runs a full range port scan, then runs a thorough scan on new ports (~5-10 minutes)
    UDP:	Runs "Basic" on UDP ports (~5 minutes)   
    Vulners:	Runs CVE scan and nmap Vulns scan on all found ports (~5-15 minutes)
    Recon:	Runs "Basic" scan "if not yet run", then suggests recon commands "i.e. gobuster, nikto, smbmap" based on the found ports, then prompts to automatically run them
    Complete: Runs all the scans consecutively (~20-30 minutes)

I barrowed the concept from <a href="https://github.com/21y4d/nmapAutomator">21y4d (nmapAutomator)</a>,<a href="https://github.com/Tib3rius/AutoRecon">Tib3rius (AutoRecon)</a>,<a href="https://github.com/jmortega/europython_ethical_hacking">jmortega (europython_ethical_hacking)</a>,and <a href="https://github.com/leebaird">leebaird(discover.sh)</a>, so thank you guys

Feel free to send your pull requests and contributions :)
Requirements:

Required: Gobuster v3.0 or higher, as it is not backward compatible.
You can update gobuster on kali using:

apt-get update
apt-get install gobuster --only-upgrade  

Other Recon tools used within the script include:

    nmap Vulners
    sslscan
    nikto
    joomscan
    wpscan
    droopescan
    smbmap
    enum4linux
    dnsrecon
    odat

Examples of use:

./nmapAutomator.sh <TARGET-IP> <TYPE>  
./nmapAutomator.sh 10.1.1.1 All  
./nmapAutomator.sh 10.1.1.1 Basic  
./nmapAutomator.sh 10.1.1.1 Recon  

If you want to use it anywhere on the system, create a shortcut using:
ln -s /PATH-TO-FOLDER/nmapAutomator.sh /usr/local/bin/
