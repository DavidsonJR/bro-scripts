# This Module is designed to detect DNSCAT2 a (A mailcious DNS tunneling software 
# for Command and Control) traffic. It was written as a proof of concept.
#
# Authors: Stephan Davidson and Ferdous Saljooki


module DNSCAT2;

event dns_request (c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
	local elements = split_string(query, /\./);
	if ((|elements| > 1) && (elements[0] == "dnscat")) {
		print fmt("Proof of Concept - DNSCAT detected!");
	}
}
