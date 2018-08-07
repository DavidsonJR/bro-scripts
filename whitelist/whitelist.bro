# This module contains a list of some of the common dns servers and well-known dns ports. 
# This is used to detect direct tunnelling from an unauthorized dns server.
#
# Written by Stephan Davidson and Ferdous Saljooki

#module WHITELIST;

global dns_whitelist = {
	8.8.8.8, #Google
	8.8.4.4, #Google
	2.2.2.2, #L3 Communications
	2.2.2.3, #L3 Communications
	10.0.1.1, #Gateway / Defined DNS by Company Policy. Add others, as needed.
	10.0.1.255, #Broadcast Address
	224.0.0.251, #mDNS
	224.0.0.252 
};

global dns_ports = {
	53/udp,
	53/tcp,
	5353/udp,
	5355/udp,
	137/udp
};
