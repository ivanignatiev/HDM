HDM
===

EPITECH Network Security II Project, Man in Middle Software

Virtual Network installation:

VM Gateway / Ubuntu Server

hostname: gateway
user: gateway
pass: gateway

timezone: Europe/Paris
OpenSSH, DNS
NAT

host-only adapter:
ip: 192.168.10.1
mask: 255.255.255.0


/etc/sysctl.conf ip_forward
net.ipv4.ip_forward=1

/etc/network/interfaces 
auto eth1
iface eth1 inet static
address 192.168.10.1
broadcast 192.168.10.254
network 192.168.10.0

/etc/rc.local  iptables

/sbin/itables -P FORWARD ACCEPT
/sbin/iptables --table nat -A POSTROUTING -o eth0 -j MASQUERADE


VM Victim

hostname: victim
user: victim
pass: victim
timezone: Europe/Paris
host-only adapter:
ip: 192.168.10.2
mask: 255.255.255.0


VM Attacker

hostname: attacker
user: attacker
pass: attacker
timezone: Europe/Paris
host-only adapter:
ip: 192.168.10.3
mask: 255.255.255.0

mongodb (pymongo)
scapy
