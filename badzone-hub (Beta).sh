#!/bin/bash

# Config
IP="0.0.0.0"
TAP="$TAP"
SSH_TIME="60" # Time of block
SSH_ERROR="3" # How many failure logins?

# Vars for messages
PATCH1="Loading important things.."
PATCH2="Important things downloaded/updated"
DEPEND1="Packets (Software) Installed/Updated"
FLOOD="Patching popular floods.."
FLOOD_END="Popular flood methods patched!"
RAPES="Rapes range applying.."
RAPES_END="Rapes ranges applied!"
OVH="Patching exploits from other DC.."
DOS="Patching DOS attacks.."
DOS_END="Patched DOS attacks!"

# Secure patching
echo $PATCH1
apt-get update
apt install wget
apt install curl
echo $PATCH2

# Setting up nload/tcpdump/dstat
apt install nload
apt install tcpdump
apt install dstat
apt install ipset
apt install netfilter
apt install nethog

iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP
iptables -t mangle -A PREROUTING -p tcp ! --syn -m conntrack --ctstate NEW -j DROP

echo $DEPEND1

# Flood patch
echo $FLOOD
iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -p tcp --dport 21 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 10000 -s 192.168.1.0/24 -j ACCEPT
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP 
iptables -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,PSH,URG -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,ACK,URG -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags ACK,URG URG -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags PSH,ACK PSH -j DROP
echo $FLOOD_END

# Block traffic instant
iptables -t mangle -A PREROUTING -p tcp -m conntrack --ctstate NEW -m tcpmss ! --mss 536:65535 -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp -m multiport --destination-ports 100:60000 -j DROP

# SSH
iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --set
iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds $SSH_TIME --hitcount $SSH_ERROR -j DROP

# UDPrapes ranges
echo $RAPES
ipset -N udprape nethash
ipset -q -A udprape 155.133.246.0/23
ipset -q -A udprape 155.133.248.0/24
ipset -q -A udprape 162.254.192.0/24
ipset -q -A udprape 162.254.193.0/24
ipset -q -A udprape 13.107.14.0/24
ipset -q -A udprape 52.112.0.0/14
ipset -q -A udprape 216.58.215.0/24
ipset -q -A udprape 216.239.36.0/24
ipset -q -A udprape 67.199.248.0/24
ipset -q -A udprape 66.249.64.0/20
ipset -q -A udprape 163.172.0.0/16
ipset -q -A udprape 50.22.130.64/27
ipset -q -A udprape 211.239.128.0/18
ipset -q -A udprape 217.72.192.0/20
ipset -q -A udprape 77.247.111.0/24
ipset -q -A udprape 37.49.231.0/24
ipset -q -A udprape 37.49.228.0/24
ipset -N cloudflare nethash
ipset -q -A cloudflare 173.245.48.0/20
ipset -q -A cloudflare 103.21.244.0/22
ipset -q -A cloudflare 103.22.200.0/22
ipset -q -A cloudflare 103.31.4.0/22
ipset -q -A cloudflare 141.101.64.0/18
ipset -q -A cloudflare 108.162.192.0/18
ipset -q -A cloudflare 190.93.240.0/20
ipset -q -A cloudflare 188.114.96.0/20
ipset -q -A cloudflare 197.234.240.0/22
ipset -q -A cloudflare 198.41.128.0/17
ipset -q -A cloudflare 162.158.0.0/15
ipset -q -A cloudflare 104.16.0.0/12
ipset -q -A cloudflare 172.64.0.0/13
ipset -q -A cloudflare 131.0.72.0/22

iptables -A PREROUTING -t mangle -p UDP -m comment --comment "non dns traffic from cloudflare" -m set --match-set cloudflare src ! --sport 53 -d $IP -j DROP
iptables -A PREROUTING -t mangle -p UDP -m comment --comment "whitelisted udp ips on the game" -m set --match-set udprape src -d $IP -j DROP
echo $RAPES_END

echo $OVH
iptables -t mangle -A PREROUTING -s 217.224.179.122 -j DROP
iptables -A INPUT -p tcp -m length --length 52 -j DROP
iptables -A INPUT -p tcp -i $TAP ! -s 0.0.0.0/0 --dport 32992 -j DROP
iptables -A OUTPUT -p tcp --dport 14335 -j DROP
iptables -t mangle -A PREROUTING -s 77.87.34.51 -j DROP
iptables -A INPUT -p udp -m length --length 52 -j DROP
iptables -A INPUT -p udp -i $TAP ! -s 0.0.0.0/0 --dport 43193 -j DROP
iptables -A OUTPUT -p udp --dport 14335 -j DROP
iptables -t mangle -A PREROUTING -s 46.201.226.158 -j DROP
iptables -A INPUT -p udp -m length --length 740 -j DROP

echo $DOS
# BZ-AntiDDoS
# Please, write: # sync; echo 3 > /proc/sys/vm/drop_caches for faster job.
 
PREFIX="[Bad Zone-Module]"

# BlockHole for reject connections
ipset -N myBlackhole-4 hash:net family inet
ipset -N myBlackhole-6 hash:net family inet6

function yep_ipset () {
# Get super bad ASN ips
	BAD_IPV4=$(curl -s https://raw.githubusercontent.com/Rezanans-wow/antiddos/main/ip-db/bad_ip)
	if [ $? -ne 0 ]; then
		echo "$PREFIX Failed download bad IP list! Firewall blocking requests to github? No internet connection?"
		return 1
	fi
# What u do?
	for i in $(echo "$BAD_IPV4"); do
		ipset -A myBlackhole-4 $bad_ipv4 $i
		echo "$PREFIX Added $i to bad_ipv4 ipset."
	done

	return 0
}

function yep_iptables () {
	if ! package_exists "iptables"; then
		echo "$PREFIX I think iptables is required for using this bash script."
		return 1
	fi
		if ! iptables -A INPUT -m set --match-set myBlackhole-4 src -j DROP; then
		iptables -A INPUT -m set --match-set myBlackhole-4 src -j DROP
	fi
    	if ! package_exists "ip6tables"; then
		# Optional
		return 0
	fi
	if ! ip6tables -A INPUT -m set --match-set myBlackhole-6 src -j DROP; then
		ip6tables -A INPUT -m set --match-set myBlackhole-6 src -j DROP
	fi
	return 0
    
}

function package_exists () {
	if ! type "$1" > /dev/null; then
		return 1
	else
		return 0
	fi
}

if yep_ipset == 0; then
	if yep_iptables == 0; then
		echo "$PREFIX We are do it! Your iptables configuration loaded, have a nice day :)"
		iptables -t mangle -A PREROUTING -m conntrack --ctstate INVALID -j DROP
		iptables -A INPUT -p udp -m u32 --u32 "26&0xFFFFFFFF=0xfeff" -j DROP
		iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
		#iptables -A INPUT -p tcp -m multiport --destination-ports 100:60000 -j DROP
		iptables -A INPUT -p udp --dport 1900 -j DROP # SSDP Fix UDP
		iptables -A INPUT -p icmp -m icmp --icmp-type address-mask-request -j DROP
                iptables -A INPUT -p icmp -m icmp --icmp-type timestamp-request -j DROP
                iptables -A INPUT -p icmp -m icmp --icmp-type 8 -m limit --limit 1/second -j ACCEPT
		iptables-save
	else
		echo "$PREFIX Failed to configure IPTABLES."
	fi
else
	echo "$PREFIX Failed to generate ipsets, script crashed."
fi

# iptables for BlackHole

iptables -A INPUT -m set --match-set myBlackhole-4 src -j DROP
ip6tables -A INPUT -m set --match-set myBlackhole-6 src -j DROP
echo "$PREFIX | Operation finished, with reserve mode"

echo $DOS_END

# Smurf Attacks
iptables -A INPUT -m pkttype --pkt-type broadcast -j DROP
iptables -A INPUT -p ICMP --icmp-type echo-request -m pkttype --pkttype broadcast -j DROP
iptables -A INPUT -p ICMP --icmp-type echo-request -m limit --limit 3/s -j ACCEPT
iptables -A INPUT -p icmp -m icmp --icmp-type address-mask-request -j DROP
iptables -A INPUT -p icmp -m icmp --icmp-type timestamp-request -j DROP
iptables -A INPUT -p icmp -m icmp -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT
iptables -A INPUT -p UDP --dport 7 -j DROP
iptables -A INPUT -p UDP --dport 19 -j DROP
iptables -A INPUT -p tcp -m connlimit --connlimit-above 80 -j REJECT --reject-with tcp-reset

# DNS
iptables -A INPUT -i $TAP -p udp --sport 53 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o $TAP -p udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT

iptables -A INPUT -i $TAP -p tcp --sport 53 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o $TAP -p tcp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT

# ICMP Bye!
iptables -A INPUT -p ICMP -f -j DROP

# Rescue rules, delete/comment it got problems
iptables -I INPUT -p udp --dport 16000:29000 -m string --to 75 --algo bm --string 'HTTP/1.1 200 OK' -j DROP
iptables -I INPUT -p udp -m udp -m string --hex-string "|7374640000000000|" --algo kmp --from 28 --to 29 -j DROP
iptables -A INPUT -p udp -m u32 --u32 "6&0xFF=0,2:5,7:16,18:255" -j DROP
iptables -A INPUT -m u32 --u32 "12&0xFFFF=0xFFFF" -j DROP
iptables -A INPUT -m u32 --u32 "28&0x00000FF0=0xFEDFFFFF" -j DROP
iptables -A INPUT -m string --algo bm --from 28 --to 29 --string "farewell" -j DROP
iptables -A INPUT -p udp -m u32 --u32 "28 & 0x00FF00FF = 0x00200020 && 32 & 0x00FF00FF = 0x00200020 && 36 & 0x00FF00FF = 0x00200020 && 40 & 0x00FF00FF = 0x00200020" -j DROP
iptables -I INPUT -p udp -m udp -m string --hex-string "|53414d50|" --algo kmp --from 28 --to 29 -j DROP
iptables -A PREROUTING -t raw -p udp --dport 9987 -m length --length 0:32 -j DROP
iptables -A PREROUTING -t raw -p udp --dport 9987 -m length --length 2521:65535 -j DROP
iptables -A PREROUTING -t raw -p udp --dport 9987 -m length --length 98 -j DROP
iptables -A INPUT -p tcp -ack -m length --length 52 -m string --algo bm --string "0x912e" -m state --state ESTABLISHED  -j DROP #Yubina-Kill-ACK
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -m limit --limit 50/s -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -m limit --limit 50/s -j DROP
iptables -A FORWARD -p tcp --syn -m limit --limit 1/s -j ACCEPT
iptables -A FORWARD -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j ACCEPT
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -m limit --limit 50/s -j ACCEPT
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -A INPUT -p tcp -rst -m length --length 40 -m string --algo bm --string "0xd3da" -m state --state ESTABLISHED  -j DROP #Yubina-RST
iptables -A INPUT -p tcp -ack -m length --length 40 -m string --algo bm --string "0x0c54" -m state --state ESTABLISHED  -j DROP # Super rescue for Minecraft servers
iptables -A INPUT -p tcp -rst -m length --length 40 -m string --algo bm --string "0x0c54" -m state --state ESTABLISHED  -j DROP # Super rescue for Minecraft servers
iptables -A INPUT -p tcp -syn -m length --length 40 -m string --algo bm --string "0x0c54" -m state --state ESTABLISHED  -j DROP # Super rescue for Minecraft servers
iptables -A INPUT -p tcp -fin -m length --length 40 -m string --algo bm --string "0x0c54" -m state --state ESTABLISHED  -j DROP # Super rescue for Minecraft servers
iptables -A INPUT -p tcp -psh -m length --length 40 -m string --algo bm --string "0x0c54" -m state --state ESTABLISHED  -j DROP # Super rescue for Minecraft servers
iptables -A INPUT -p tcp -ack -m length --length 40 -m string --algo bm --string "0x38d3" -m state --state ESTABLISHED  -j DROP # Super rescue for Minecraft servers
iptables -A INPUT -p tcp -rst -m length --length 40 -m string --algo bm --string "0x38d3" -m state --state ESTABLISHED  -j DROP # Super rescue for Minecraft servers
iptables -A INPUT -p tcp -syn -m length --length 40 -m string --algo bm --string "0x38d3" -m state --state ESTABLISHED  -j DROP # Super rescue for Minecraft servers
iptables -A INPUT -p tcp -fin -m length --length 40 -m string --algo bm --string "0x38d3" -m state --state ESTABLISHED  -j DROP # Super rescue for Minecraft servers
iptables -A INPUT -p tcp -psh -m length --length 40 -m string --algo bm --string "0x38d3" -m state --state ESTABLISHED  -j DROP # Super rescue for Minecraft servers
iptables -A INPUT -p tcp -ack -m length --length 40 -m string --algo bm --string "0x0c54" -m state --state ESTABLISHED  -j DROP # Super rescue for Minecraft servers
iptables -A INPUT -p tcp -rst -m length --length 40 -m string --algo bm --string "0x0c54" -m state --state ESTABLISHED  -j DROP # Super rescue for Minecraft servers
iptables -A INPUT -p tcp -syn -m length --length 40 -m string --algo bm --string "0x0c54" -m state --state ESTABLISHED  -j DROP # Super rescue for Minecraft servers
iptables -A INPUT -p tcp -fin -m length --length 40 -m string --algo bm --string "0x0c54" -m state --state ESTABLISHED  -j DROP # Super rescue for Minecraft servers
iptables -A INPUT -p tcp -psh -m length --length 40 -m string --algo bm --string "0x0c54" -m state --state ESTABLISHED  -j DROP # Super rescue for Minecraft servers
iptables -A INPUT -p tcp -ack -m length --length 40 -m string --algo bm --string "0xd3da" -m state --state ESTABLISHED  -j DROP # Super rescue for Minecraft servers
iptables -A INPUT -p tcp -rst -m length --length 40 -m string --algo bm --string "0xd3da" -m state --state ESTABLISHED  -j DROP # Super rescue for Minecraft servers
iptables -A INPUT -p tcp -syn -m length --length 40 -m string --algo bm --string "0xd3da" -m state --state ESTABLISHED  -j DROP # Super rescue for Minecraft servers
iptables -A INPUT -p tcp -fin -m length --length 40 -m string --algo bm --string "0xd3da" -m state --state ESTABLISHED  -j DROP # Super rescue for Minecraft servers
iptables -A INPUT -p tcp -psh -m length --length 40 -m string --algo bm --string "0xd3da" -m state --state ESTABLISHED  -j DROP # Super rescue for Minecraft servers
iptables -A INPUT -p tcp -ack -m length --length 40 -m string --algo bm --string "0x912e" -m state --state ESTABLISHED  -j DROP # Super rescue for Minecraft servers
iptables -A INPUT -p tcp -rst -m length --length 40 -m string --algo bm --string "0x912e" -m state --state ESTABLISHED  -j DROP # Super rescue for Minecraft servers
iptables -A INPUT -p tcp -syn -m length --length 40 -m string --algo bm --string "0x912e" -m state --state ESTABLISHED  -j DROP # Super rescue for Minecraft servers
iptables -A INPUT -p tcp -fin -m length --length 40 -m string --algo bm --string "0x912e" -m state --state ESTABLISHED  -j DROP # Super rescue for Minecraft servers
iptables -A INPUT -p tcp -psh -m length --length 40 -m string --algo bm --string "0x912e" -m state --state ESTABLISHED  -j DROP # Super rescue for Minecraft servers
iptables -A INPUT -m string --algo bm --string "" -j DROP #Empty Long IT/STR/PL
iptables -A INPUT -m string --algo bm --string "U" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings
iptables -A INPUT -m string --algo bm --string "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU" -j DROP #SAO-UDP Strings



iptables -A INPUT -m string --algo bm --string "\x77" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47\x5E" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47\x5E\x27" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47\x5E\x27\x7A" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47\x5E\x27\x7A\x4E\x09" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47\x5E\x27\x7A\x4E\x09\xF7\xC7" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47\x5E\x27\x7A\x4E\x09\xF7\xC7\xC0\xE6" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47\x5E\x27\x7A\x4E\x09\xF7\xC7\xC0\xE6\xF5\x9B" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47\x5E\x27\x7A\x4E\x09\xF7\xC7\xC0\xE6\xF5\x9B\xDC\x23" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47\x5E\x27\x7A\x4E\x09\xF7\xC7\xC0\xE6\xF5\x9B\xDC\x23\x6E\x12" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47\x5E\x27\x7A\x4E\x09\xF7\xC7\xC0\xE6\xF5\x9B\xDC\x23\x6E\x12\x29\x25" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47\x5E\x27\x7A\x4E\x09\xF7\xC7\xC0\xE6\xF5\x9B\xDC\x23\x6E\x12\x29\x25\x1D\x0A" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47\x5E\x27\x7A\x4E\x09\xF7\xC7\xC0\xE6\xF5\x9B\xDC\x23\x6E\x12\x29\x25\x1D\x0A\xEF\xFB" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47\x5E\x27\x7A\x4E\x09\xF7\xC7\xC0\xE6\xF5\x9B\xDC\x23\x6E\x12\x29\x25\x1D\x0A\xEF\xFB\xDE\xB6" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47\x5E\x27\x7A\x4E\x09\xF7\xC7\xC0\xE6\xF5\x9B\xDC\x23\x6E\x12\x29\x25\x1D\x0A\xEF\xFB\xDE\xB6\xB1\x94" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47\x5E\x27\x7A\x4E\x09\xF7\xC7\xC0\xE6\xF5\x9B\xDC\x23\x6E\x12\x29\x25\x1D\x0A\xEF\xFB\xDE\xB6\xB1\x94\xD6" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -m string --algo bm --string "\x77\x47\x5E\x27\x7A\x4E\x09\xF7\xC7\xC0\xE6\xF5\x9B\xDC\x23\x6E\x12\x29\x25\x1D\x0A\xEF\xFB\xDE\xB6\xB1\x94\xD6\x7A\x6B" -j DROP #OVH-SMACK Bypass Strings/
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags PSH,ACK PSH -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags ACK,URG URG -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,PSH,URG -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,ACK,URG -j DROP
iptables -A INPUT -p tcp -m tcp --sport 443 --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -m limit --limit 400/sec --limit-burst 15 -j ACCEPT
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -j DROP  iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP iptables -A INPUT -m state --state RELATED,ESTABLISHED -m limit --limit 10/sec --limit-burst 15 -j ACCEPT
iptables -A INPUT -p tcp --sport 80 --syn -m state --state NEW -m limit --limit 400/sec --limit-burst 15 -j ACCEPT iptables -A INPUT -p tcp -m connlimit --connlimit-above 150 -j DROP iptables -A INPUT -p tcp --sport 443 --syn -m state --state NEW -m limit --limit 400/sec --limit-burst 15 -j ACCEPT iptables -FORWARD DROP ovh kill patch
iptables -I INPUT -p udp -m udp -m string --hex-string "|ffbbbfefbbbeffbbbfebffffefbbbf30783030303230303031|" --algo kmp -j DROP
iptables -I INPUT -p udp -m udp -m string --hex-string "|f0ffffffef6765746368616c6c656e676520302022|" --algo kmp -j ACCEPT
iptables -I INPUT -p udp -m udp -m string --hex-string "|c0cf0fffef6765746368616c6c656e676520302022|" --algo kmp -j DROP
iptables -A OUTPUT ! -s 127.198.148.58/32 ! -d 127.77.75.129/32 -p icmp -m icmp --icmp-type 3/3 -m connmark ! --mark 0x7ba5407d -j DROP
iptables -A OUTPUT ! -s 127.231.45.126/32 ! -d 127.20.246.233/32 -p tcp -m tcp --sport 61001:65535 --tcp-flags RST RST -m connmark ! --mark 0x407ee413 -j DROP
iptables -A OUTPUT ! -s 127.198.148.58/32 ! -d 127.77.75.129/32 -p icmp -m icmp --icmp-type 3/3 -m connmark ! --mark 0x7ba5407d -j DROP
iptables -A OUTPUT ! -s 127.231.45.126/32 ! -d 127.20.246.233/32 -p tcp -m tcp --sport 61001:65535 --tcp-flags RST RST -m connmark ! --mark 0x407ee413 -j DROP
iptables -A INPUT -p tcp -ack -m length --length 52 -m string --algo bm --string "0x912e" -m state --state ESTABLISHED  -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -m limit --limit 50/s -j DROP
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -m limit --limit 50/s -j DROP
iptables -A FORWARD -p tcp --syn -m limit --limit 1/s -j ACCEPT
iptables -A FORWARD -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j ACCEPT
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -m limit --limit 50/s -j ACCEPT
iptables -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -t mangle -A PREROUTING -p udp -m multiport --sports 3283,37810,7001,17185,3072,3702,32414,177,6881,5683,41794,2362,11211,53413,17,1900,10001,389,137,5351,502 -j DROP
iptables -t mangle -A PREROUTING -p udp --sport 37810 -j DROP
iptables -t mangle -A PREROUTING -p udp --sport 7001 -j DROP
iptables -I INPUT -p udp -m length --length 100:140 -m string --string "nAFS" --algo kmp -j DROP
iptables -I INPUT -p udp -m length --length 100:140 -m string --string "OpenAFS" --algo kmp -j DROP
iptables -t mangle -A PREROUTING -p udp --sport 17185 -j DROP
iptables -t mangle -A PREROUTING -p udp -m multiport --sports 3072,3702 -j DROP
iptables -t mangle -A PREROUTING -p tcp -m multiport --sports 3072,3702 -j DROP
iptables -t mangle -A PREROUTING -p udp --sport 3283 -m length --length 1048 -j DROP
iptables -t mangle -A PREROUTING -p udp --sport 3283 -m length --length 1048 -j DROP
iptables -t mangle -A PREROUTING -p udp --sport 32414 -j DROP
iptables -t mangle -A PREROUTING -p udp --sport 177 -j DROP
iptables -t mangle -A PREROUTING -p udp --sport 6881 -m length --length 320:330 -j DROP
iptables -t mangle -A PREROUTING -p udp -m length --length 280:300 --sport 32414 -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags PSH,ACK PSH -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags ACK,URG URG -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,PSH,URG -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,ACK,URG -j DROP
iptables -A INPUT -p tcp -m tcp --sport 443 --tcp-flags SYN,ACK SYN,ACK -m state --state NEW -m limit --limit 400/sec --limit-burst 15 -j ACCEPT
iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
iptables -A INPUT -p tcp -m tcp --tcp-flags SYN,ACK SYN,ACK -j DROP  iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP iptables -A INPUT -m state --state RELATED,ESTABLISHED -m limit --limit 10/sec --limit-burst 15 -j ACCEPT
iptables -A INPUT -p tcp --sport 80 --syn -m state --state NEW -m limit --limit 400/sec --limit-burst 15 -j ACCEPT iptables -A INPUT -p tcp -m connlimit --connlimit-above 150 -j DROP 
iptables -A INPUT -p tcp --sport 443 --syn -m state --state NEW -m limit --limit 400/sec --limit-burst 15 -j ACCEPT iptables -FORWARD DROP ovh kill patch
iptables -A INPUT -s 127.0.0.0/8 -d 127.0.0.0/8 -j ACCEPT
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -p tcp -m tcp -m connlimit --connlimit-above 8 --connlimit-mask 32 --connlimit-saddr -j DROP
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p icmp -m icmp ! --icmp-type 8 -j ACCEPT
iptables -P INPUT DROP
iptables -N ovh_rape
iptables -A INPUT -p udp -m string --algo kmp --hex-string "|fe fe fe fe fe|" --from 28 -j ovh_rape
iptables -A ovh_rape -m limit --limit 100/s --limit-burst 500 -j RETURN
iptables -A ovh_rape -j DROP
ipset -N ovh_rape
iptables -t raw -A PREROUTING -s 155.133.246.0/23 -j DROP
iptables -t raw -A PREROUTING -s 155.133.248.0/24 -j DROP
iptables -t raw -A PREROUTING -s 162.254.192.0/24 -j DROP
iptables -t raw -A PREROUTING -s 162.254.193.0/24 -j DROP
iptables -t raw -A PREROUTING -s 13.107.14.0/24 -j DROP
iptables -t raw -A PREROUTING -s 52.112.0.0/14 -j  DROP
iptables -t raw -A PREROUTING -s 216.58.215.0/24 -j DROP
iptables -t raw -A PREROUTING -s 216.239.36.0/24 -j DROP
iptables -t raw -A PREROUTING -s 67.199.248.0/24 -j DROP
iptables -t raw -A PREROUTING -s 66.249.64.0/20 -j DROP
iptables -N ovh_rape
iptables -A INPUT -p udp -m set --match-set ovh_rape src -m limit -j ovh_rape
iptables -A ovh_rape -m limit --limit 1000/s -j RETURN
iptables -A ovh_rape -j DROP
iptables -A INPUT -p tcp -m connlimit --connlimit-above 80 -j REJECT --reject-with tcp-reset
iptables -t mangle -A PREROUTING -f -j DROP
iptables -t mangle -A PREROUTING -f -j DROP
iptables -A INPUT -p udp -m multiport --dports 135,137,138,139,445,1433,1434 -j DROP
iptables -A INPUT -p tcp -m multiport --dports 135,137,138,139,445,1433,1434 -j DROP
iptables -A INPUT -p udp -m multiport --sports 135,137,138,139,445,1433,1434 -j DROP
iptables -A INPUT -p tcp -m multiport --sports 135,137,138,139,445,1433,1434 -j DROP
iptables -A INPUT -p udp -m multiport --dports 853,4433,4740,5349,5684,5868,6514,6636,8232,10161 -j DROP
iptables -A INPUT -p tcp -m multiport --dports 853,4433,4740,5349,5684,5868,6514,6636,8232,10161 -j DROP
iptables -A INPUT -p udp -m multiport --sports 853,4433,4740,5349,5684,5868,6514,6636,8232,10161 -j DROP
iptables -A INPUT -p tcp -m multiport --sports 853,4433,4740,5349,5684,5868,6514,6636,8232,10161 -j DROP
iptables -A INPUT -p udp -m multiport --dports 10162,12346,12446,12546,12646,12746,12846,12946,13046 -j DROP
iptables -A INPUT -p tcp -m multiport --dports 10162,12346,12446,12546,12646,12746,12846,12946,13046 -j DROP
iptables -A INPUT -p udp -m multiport --sports 10162,12346,12446,12546,12646,12746,12846,12946,13046 -j DROP
iptables -A INPUT -p tcp -m multiport --sports 10162,12346,12446,12546,12646,12746,12846,12946,13046 -j DROP
iptables -A INPUT -p udp -m multiport --dports 1645,1812,2049,3283,2302,6481,17185,26000,26001,26002 -j DROP
iptables -A INPUT -p tcp -m multiport --dports 1645,1812,2049,3283,2302,6481,17185,26000,26001,26002 -j DROP
iptables -A INPUT -p udp -m multiport --sports 1645,1812,2049,3283,2302,6481,17185,26000,26001,26002 -j DROP
iptables -A INPUT -p tcp -m multiport --sports 1645,1812,2049,3283,2302,6481,17185,26000,26001,26002 -j DROP
iptables -A INPUT -p udp -m multiport --dports 26003,26004,27960,27961,27962,27963,27964,30720,30721 -j DROP
iptables -A INPUT -p tcp -m multiport --dports 26003,26004,27960,27961,27962,27963,27964,30720,30721 -j DROP
iptables -A INPUT -p udp -m multiport --sports 26003,26004,27960,27961,27962,27963,27964,30720,30721 -j DROP
iptables -A INPUT -p tcp -m multiport --sports 26003,26004,27960,27961,27962,27963,27964,30720,30721 -j DROP
iptables -A INPUT -p udp -m multiport --dports 30722,30723,30724,44400,3784,64378,8767,11211,1645,1812,520 -j DROP
iptables -A INPUT -p tcp -m multiport --dports 30722,30723,30724,44400,3784,64378,8767,11211,1645,1812,520 -j DROP
iptables -A INPUT -p udp -m multiport --sports 30722,30723,30724,44400,3784,64378,8767,11211,1645,1812,520 -j DROP
iptables -A INPUT -p tcp -m multiport --sports 30722,30723,30724,44400,3784,64378,8767,11211,1645,1812,520 -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "\x00","\x01","\x02","\x03","\x04","\x05","\x06","\x07","\x08","\x09","\x0a","\x0b","\x0c","\x                                   0d","\x0e","\x0f","\x10","\x11","\x12","\x13","\x14","\x15","\x16","\x17","\x18","\x19","\x1a","\x1b","\x1c","\x1d","\x1e","\x1f","\x20","\x21","\x22","\x23","                                   \x24","\x25","\x26","\x27","\x28","\x29","\x2a","\x2b","\x2c","\x2d","\x2e","\x2f","\x30","\x31","\x32","\x33","\x34","\x35","\x36","\x37","\x38","\x39","\x3a"                                   ,"\x3b","\x3c","\x3d","\x3e","\x3f","\x40","\x41","\x42","\x43","\x44","\x45","\x46","\x47","\x48","\x49","\x4a","\x4b","\x4c","\x4d","\x4e","\x4f","\x50","\x5                                   1","\x52","\x53","\x54","\x55","\x56","\x57","\x58","\x59","\x5a","\x5b","\x5c","\x5d","\x5e","\x5f","\x60","\x61","\x62","\x63","\x64","\x65","\x66","\x67","\                                   x68","\x69","\x6a","\x6b","\x6c","\x6d","\x6e","\x6f","\x70","\x71","\x72","\x73","\x74","\x75","\x76","\x77","\x78","\x79","\x7a","\x7b","\x7c","\x7d","\x7e",                                   "\x7f","\x80","\x81","\x82","\x83","\x84","\x85","\x86","\x87","\x88","\x89","\x8a","\x8b","\x8c","\x8d","\x8e","\x8f","\x90","\x91","\x92","\x93","\x94","\x95                                   ","\x96","\x97","\x98","\x99","\x9a","\x9b","\x9c","\x9d","\x9e","\x9f","\xa0","\xa1","\xa2","\xa3","\xa4","\xa5","\xa6","\xa7","\xa8","\xa9","\xaa","\xab","\x                                   ac","\xad","\xae","\xaf","\xb0","\xb1","\xb2","\xb3","\xb4","\xb5","\xb6","\xb7","\xb8","\xb9","\xba","\xbb","\xbc","\xbd","\xbe","\xbf","\xc0","\xc1","\xc2","                                   \xc3","\xc4","\xc5","\xc6","\xc7","\xc8","\xc9","\xca","\xcb","\xcc","\xcd","\xce","\xcf","\xd0","\xd1","\xd2","\xd3","\xd4","\xd5","\xd6","\xd7","\xd8","\xd9"                                   ,"\xda","\xdb","\xdc","\xdd","\xde","\xdf","\xe0","\xe1","\xe2","\xe3","\xe4","\xe5","\xe6","\xe7","\xe8","\xe9","\xea","\xeb","\xec","\xed","\xee","\xef","\xf                                   0","\xf1","\xf2","\xf3","\xf4","\xf5","\xf6","\xf7","\xf8","\xf9","\xfa","\xfb","\xfc","\xfd","\xfe","\xff" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string ""\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01"" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x05\x00\x01" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "\x72\xFE\x1D\x13\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xA0\x00\x01\x97\x7C\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "\xd9\x00\x0a\xfa\x00\x00\x00\x00\x00\x01\x02\x90\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc5\x02\x04\xec\xec\x42\xee\x92" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x05\x00\x01" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "\x30\x3A\x02\x01\x03\x30\x0F\x02\x02\x4A\x69\x02\x03\x00\xFF\xE3\x04\x01\x04\x02\x01\x03\x04\       x10\x30\x0E\x04\x00\x02\x01\x00\x02\x01\x00\x04\x00\x04\x00\x04\x00\x30\x12\x04\x00\x04\x00\xA0\x0C\x02\x02\x37\xF0\x02\x01\x00\x02\x01\x00\x30\x00" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "\x00\x01\x00\x02\x00\x01\x00" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "\x30\x84\x00\x00\x00\x2d\x02\x01\x07\x63\x84\x00\x00\x00\x24\x04\x00\x0a\x01\x00\x0a\x01\x00\       x02\x01\x00\x02\x01\x64\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x43\x6c\x61\x73\x73\x30\x84\x00\x00\x00\x00" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "\x00\x11\x22\x33\x44\x55\x66\x77\x00\x00\x00\x00\x00\x00\x00\x00\x01\x10\x02\x00\x00\x00\x00\       x00\x00\x00\x00\xC0\x00\x00\x00\xA4\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x98\x01\x01\x00\x04\x03\x00\x00\x24\x01\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00       \x02\x80\x03\x00\x01\x80\x04\x00\x02\x80\x0B\x00\x01\x00\x0C\x00\x04\x00\x00\x00\x01\x03\x00\x00\x24\x02\x01\x00\x00\x80\x01\x00\x05\x80\x02\x00\x01\x80\x03\x0       0\x01\x80\x04\x00\x02\x80\x0B\x00\x01\x00\x0C\x00\x04\x00\x00\x00\x01\x03\x00\x00\x24\x03\x01\x00\x00\x80\x01\x00\x01\x80\x02\x00\x02\x80\x03\x00\x01\x80\x04\x00\x02\x80\x0B\x00\x01\x00\x0C\x00\x04\x00\x00\x00\x01" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "\x06\x00\xff\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x20\x18\xc8\x81\x00\x38\x8e\x04\xb5"-j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "SNQUERY: 127.0.0.1:AAAAAA:xsvr" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "8d\xc1x\x01\xb8\x9b\xcb\x8f\0\0\0\0\0" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "\x02" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "\x1e\x00\x01\x30\x02\xfd\xa8\xe3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "\x4d\x2d\x53\x45\x41\x52\x43\x48\x20\x2a\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a\x48\x4f\       x53\x54\x3a\x20\x32\x35\x35\x2e\x32\x35\x35\x2e\x32\x35\x35\x2e\x32\x35\x35\x3a\x31\x39\x30\x30\x0d\x0a\x4d\x41\x4e\x3a\x20\x22\x73\x73\x64\x70\x3a\x64\x69\x73       \x63\x6f\x76\x65\x72\x22\x0d\x0a\x4d\x58\x3a\x20\x31\x0d\x0a\x53\x54\x3a\x20\x75\x72\x6e\x3a\x64\x69\x61\x6c\x2d\x6d\x75\x6c\x74\x69\x73\x63\x72\x65\x65\x6e\x2       d\x6f\x72\x67\x3a\x73\x65\x72\x76\x69\x63\x65\x3a\x64\x69\x61\x6c\x3a\x31\x0d\x0a\x55\x53\x45\x52\x2d\x41\x47\x45\x4e\x54\x3a\x20\x47\x6f\x6f\x67\x6c\x65\x20\x       43\x68\x72\x6f\x6d\x65\x2f\x36\x30\x2e\x30\x2e\x33\x31\x31\x32\x2e\x39\x30\x20\x57\x69\x6e\x64\x6f\x77\x73\x0d\x0a\x0d\x0a" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0C\x00\x01" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "xf4\xbe\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x002x\xba\x85\tTeamSpeak\x00\x00\       x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\nWindows XP\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00 \x00<\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\                 x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08nickname\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "\x05\xca\x7f\x16\x9c\x11\xf9\x89\x00\x00\x00\x00\x02\x9d\x74\x8b\x45\xaa\x7b\xef\xb9\x9e\xfe\       xad\x08\x19\xba\xcf\x41\xe0\x16\xa2\x32\x6c\xf3\xcf\xf4\x8e\x3c\x44\x83\xc8\x8d\x51\x45\x6f\x90\x95\x23\x3e\x00\x97\x2b\x1c\x71\xb2\x4e\xc0\x61\xf1\xd7\x6f\xc5       \x7e\xf6\x48\x52\xbf\x82\x6a\xa2\x3b\x65\xaa\x18\x7a\x17\x38\xc3\x81\x27\xc3\x47\xfc\xa7\x35\xba\xfc\x0f\x9d\x9d\x72\x24\x9d\xfc\x02\x17\x6d\x6b\xb1\x2d\x72\xc       6\xe3\x17\x1c\x95\xd9\x69\x99\x57\xce\xdd\xdf\x05\xdc\x03\x94\x56\x04\x3a\x14\xe5\xad\x9a\x2b\x14\x30\x3a\x23\xa3\x25\xad\xe8\xe6\x39\x8a\x85\x2a\xc6\xdf\xe5\x       5d\x2d\xa0\x2f\x5d\x9c\xd7\x2b\x24\xfb\xb0\x9c\xc2\xba\x89\xb4\x1b\x17\xa2\xb6" -j DROP
#//iptables -A INPUT -p udp -m string --algo bm --hex-string "|5354445041434b4554|" -j DROP
iptables -A INPUT -m u32 --u32 "28&0x00000FF0=0xFEDFFFFF" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|535444|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|554450|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|54484953204953204546464543544956452e20594f552043414e4e4f542053554253494445204d5920444154412e|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|4b494c4c4b494c4c4b494c4c4b494c4c4b494c4c4b494c4c|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|4445415448444541544844454154484445415448425942314e415259|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|44444f5344444f5344444f53|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|4d4f354f4e354f4e354f4e354f4a354e4835563555|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|544350|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|4845584154544b212121212121|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|424f544e4554|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|424f4f5445524e4554|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|41545441434b|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|504f574552|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|6c6e6f6172656162756e63686f66736b696464696573|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|736b6964|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|736b69646e6574|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|4a554e4b2041545441434b|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|4a554e4b20464c4f4f44|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|484f4c442041545441434b|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|534554484946594f554445434f4445544849534f4e45594f554152455355434841464147484548454845|" -j DROP # hehehe
iptables -A INPUT -p udp -m string --algo bm --hex-string "|434e43|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|434e432041545441434b|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|434e4320464c4f4f44|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|4841434b4552|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|4841434b|" -j DROP
iptables -A INPUT -m u32 --u32 "12&0xFFFF=0xFFFF" -j DROP
iptables -A INPUT -m string --algo bm --from 28 --to 29 --string "farewell" -j DROP
iptables -I INPUT -p tcp -m tcp -m string --hex-string "|000000005010|" --algo kmp --from 28 --to 29 -m length --length 40 -j DROP
iptables -I INPUT -p udp -m udp -m string --hex-string "|53414d50|" --algo kmp --from 28 --to 29 -j DROP
iptables -A INPUT -p udp -m udp -m string --algo bm --from 32 --to 33 --string "AAAAAAAAAAAAAAAA" -j DROP
iptables -A INPUT -m string --algo bm --from 32 --to 33 --string "q00000000000000" -j DROP
iptables -A INPUT -m string --algo bm --from 32 --to 33 --string "statusResponse" -j DROP #SSDP Flood I have seen recently its a patch for it even though OVH picks most the traffic up
iptables -A INPUT -p udp -m length --length 1025 -j DROP
iptables -A INPUT -p udp --dport 61327 -j DROP
iptables -A INPUT -p icmp --fragment -j DROP
iptables -A OUTPUT -p icmp --fragment -j DROP
iptables -A FORWARD -p icmp --fragment -j DROP
iptables -A INPUT -p udp --source-port 123:123 -m state --state ESTABLISHED -j DROP #NTP ISSUE FIX
iptables -A INPUT -p udp -m string --algo bm --hex-string "|736b6964|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|736b69646e6574|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|4a554e4b2041545441434b|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|4a554e4b20464c4f4f44|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|484f4c442041545441434b|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|534554484946594f554445434f4445544849534f4e45594f554152455355434841464147484548454845|" -j DROP # hehehe
iptables -A INPUT -p udp -m string --algo bm --hex-string "|434e43js9273sjks|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|434e432041545441434bjsobdisbs|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|434e4320464c4f4f44|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|4841434b4552|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|4841434b|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|736b6964|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|736b69646e6574|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|4a554e4b2041545441434b|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|4a554e4b20464c4f4f44|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|484f4c442041545441434b|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|534554484946594f554445434f4445544849534f4e45594f554152455355434841464147484548454845|" -j DROP # hehehe
iptables -A INPUT -p udp -m string --algo bm --hex-string "|434e43|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|434e432ee92041545441434b|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|434e4320464c4f4f44|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|4841434b4552|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|5354445041434b4554|" -j DROP
iptables -A INPUT -m u32 --u32 "28&0x00000FF0=0xFEDFFFFF" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|535444|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|554450|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|54484953204953204546464543544956452e20594f552043414e4e4f542053554253494445204d5920444154412e|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|4b494c4c4b494c4c4b494c4c4b494c4c4b494c4c4b494c4c|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|4445415448444541544844454154484445415448425942314e415259|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|44444f5344444f5344444f53|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|4d4f354f4e354f4e354f4e354f4a354e4835563555|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|544350|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|4845584154544b212121212121|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|424f544e4554|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|424f4f5445524e4554|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|41545441434b|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|504f574552|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|6c6e6f6172656162756e63686f66736b696464696573|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|736b6964|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|736b69646e6574|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|4a554e4b2041545441434b|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|4a554e4b20464c4f4f44|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|484f4c442041545441434b|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|534554484946594f554445434f4445544849534f4e45594f554152455355434841464147484548454845|" -j DROP # hehehe
iptables -A INPUT -p udp -m string --algo bm --hex-string "|434e43|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|434e432041545441434b|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|434e4320464c4f4f44|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|4841434b4552|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|4841434b|" -j DROP
iptables -A INPUT -m u32 --u32 "12&0xFFFF=0xFFFF" -j DROP
iptables -A INPUT -m string --algo bm --from 28 --to 29 --string "farewell" -j DROP
iptables -I INPUT -p tcp -m tcp -m string --hex-string "|000000005010|" --algo kmp --from 28 --to 29 -m length --length 40 -j DROP
iptables -I INPUT -p udp -m udp -m string --hex-string "|53414d50|" --algo kmp --from 28 --to 29 -j DROP
iptables -A INPUT -p udp -m udp -m string --algo bm --from 32 --to 33 --string "AAAAAAAAAAAAAAAA" -j DROP
iptables -A INPUT -m string --algo bm --from 32 --to 33 --string "q00000000000000" -j DROP
iptables -A INPUT -m string --algo bm --from 32 --to 33 --string "statusResponse" -j DROP #SSDP Flood I have seen recently its a patch for it even though OVH picks most the traffic up
iptables -A INPUT -p udp -m length --length 1025 -j DROP
iptables -A INPUT -p udp --dport 61327 -j DROP
iptables -A INPUT -p icmp --fragment -j DROP
iptables -A OUTPUT -p icmp --fragment -j DROP
iptables -A FORWARD -p icmp --fragment -j DROP
iptables -A INPUT -p udp --source-port 123:123 -m state --state ESTABLISHED -j DROP #NTP ISSUE FIX
iptables -A INPUT -p udp -m string --algo bm --hex-string "|736b6964|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|736b69646e6574|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|4a554e4b2041545441434b|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|4a554e4b20464c4f4f44|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|484f4c442041545441434b|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|534554484946594f554445434f4445544849534f4e45594f554152455355434841464147484548454845|" -j DROP # hehehe
iptables -A INPUT -p udp -m string --algo bm --hex-string "|434e43js9273sjks|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|434e432041545441434bjsobdisbs|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|434e4320464c4f4f44|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|4841434b4552|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|4841434b|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|736b6964|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|736b69646e6574|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|4a554e4b2041545441434b|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|4a554e4b20464c4f4f44|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|484f4c442041545441434b|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|534554484946594f554445434f4445544849534f4e45594f554152455355434841464147484548454845|" -j DROP # hehehe
iptables -A INPUT -p udp -m string --algo bm --hex-string "|434e43|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|434e432ee92041545441434b|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|434e4320464c4f4f44|" -j DROP
iptables -A INPUT -p udp -m string --algo bm --hex-string "|4841434b4552|" -j DROP
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m recent --update --hitcount 10 --name SYN-DROP --seconds 86400 -j DROP
iptables -A INPUT -m recent --update --hitcount 5 --name SYN-DROP --seconds 3600 -j DROP
iptables -N SYN
iptables -A SYN -m limit --limit 10/min --limit-burst 3 -j LOG --log-level warning --log-prefix "[SYN: DROP]"
iptables -A SYN -m limit --limit 10/min --limit-burst 3 -m recent --set --name SYN-DROP -j DROP
iptables -A SYN -j DROP
iptables -A INPUT -p UDP -m length --length 1:1024 -m recent --set --name GetStatus
iptables -A INPUT -p UDP -m string --algo bm --hex-string "|ff ff ff ff 67 65 74 73 74 61 74 75 73|" -m recent --update --seconds 1 --hitcount 5 --nameGetStatus -j DROP
iptables -N syn-flood
iptables -A INPUT -i $TAP -p tcp --syn -j syn-flood
iptables -N syn-flood
iptables -A syn-flood -m limit --limit 10/sec --limit-burst 15 -j RETURN
iptables -A syn-flood -j LOG --log-prefix "SYN flood: "
iptables -A syn-flood -j DROP
iptables -N http-flood
iptables -A INPUT -p tcp --syn --dport 80 -m connlimit --connlimit-above 1 -j http-flood
iptables -A INPUT -p tcp --syn --dport 443 -m connlimit --connlimit-above 1 -j http-flood
iptables -A http-flood -m limit --limit 10/s --limit-burst 10 -j RETURN
iptables -A http-flood -m limit --limit 1/s --limit-burst 10 -j LOG --log-prefix "HTTP-FLOOD "
iptables -A http-flood -j DROP

iptables-save