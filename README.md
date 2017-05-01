# Detect-machine-LAN - Fork for the practice of Internal Networks of UCLM - ESII-2
Detect LAN machine is a software written in python to detect machines that connect to your network using nmap and using whitelist, if you find a team that is not in the whitelist can send an email notice.

Updated to work in Python 3.

Added detection with scapy.

Gtk notification icon: Incomplete.

# Usage example:

sudo python3 ./DetectMachineLan.py -r 192.168.0.0/24 --log -u myuser@gmail.com --pwd mypassword -s smtp.gmail.com -p 587 --et=emailto@gmail.com
