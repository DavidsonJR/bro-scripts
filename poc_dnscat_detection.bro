# This rule will detect DNSCAT traffic, a popular DNS Tunnelling software used for
# malicious and academic C2
#
# Authored by: Stephan Davidson and Ferdous Saljooki

event dns_request (c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
  local elements = split_string(query, /\./);
  if ((|elements| > 1) && (elements[0] == "dnscat")) {
    print "Proof of Concept - DNSCAT detected!";
  }
}
