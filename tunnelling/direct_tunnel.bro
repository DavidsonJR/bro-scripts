module TUNNELLING;

# This module is used to attempt fingerprinting of known DNS tunnelling payloads via direct
# tunnelling. This does not work for tunnelling over an actual DNS server (ie. Google).
#
# Written by Stephan Davidson and Ferdous Saljooki

event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count) {
	if (!(c$id$resp_h in dns_whitelist)) {
		if (c$id$resp_p in dns_ports) {
			if (c?$dns) {
				if (c$dns?$query) {
					#DNSCAT
					if (|(find_all(c$dns$query, /dnscat/))| == 1) {
						print fmt("Fingerprinted! DNSCAT Detected -- Attacking IP: %s | Victim IP: %s", c$id$resp_h, c$id$orig_h);
						Log::write(TUNNELLING::LOG, [$evt="DNSCAT Detected", $ts=network_time(), $id=c$id, $data=c$dns$query]);
					}
					#DNS2TCP -- Failed attempt to Fingerprint. Needs work.
					else if (|(find_all(c$dns$query, /dn8AAAA/))| == 1) {
						print fmt("Fingreprinted! DNS2TCP Detected -- Attacking IP: %s | Victim IP: %s", c$id$resp_h, c$id$orig_h);
						Log::write(TUNNELLING::LOG, [$evt="DNS2TCP Detected", $ts=network_time(), $id=c$id, $data=c$dns$query]);
					}
					#Unable to Fingerprint
					else {
						print fmt("SUSPECT DNS: %s", c$id$resp_h);
						Log::write(TUNNELLING::LOG, [$evt="Suspect DNS Detected", $ts=network_time(), $id=c$id, $data="DNS not in Whitelist. Unable to Fingerprint."]);					
					}
				}
				else {
					print fmt("SUSPECT DNS: %s", c$id$resp_h);
					Log::write(TUNNELLING::LOG, [$evt="Suspect DNS Detected", $ts=network_time(), $id=c$id, $data="DNS not in Whitelist. Empty Query."]);
				}
			}
			else {
				print fmt("SUSPECT DNS: %s", c$id$resp_h);
				Log::write(TUNNELLING::LOG, [$evt="Suspect DNS Detected", $ts=network_time(), $id=c$id, $data="DNS not in Whitlist. Port not in Whitelist."]);
			}
		} 
	}
}
