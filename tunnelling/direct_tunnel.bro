# This module is used to attempt fingerprinting of known DNS tunnelling payloads via direct
# tunnelling. This does not work for tunnelling over an actual DNS server (ie. Google).
#
# Written by Stephan Davidson and Ferdous Saljooki

module TUNNELLING;

global direct_suppression: table[int] of count &default=0 &write_expire=10secs;

event dns_message(c: connection, is_orig: bool, msg: dns_msg, len: count) {
	if (!(c$id$resp_h in dns_IPv4) && !(c$id$resp_h in dns_IPv6)) {
		if (c$id$resp_p in dns_ports) {
			if (c?$dns) {
				if (c$dns?$query) {
					#DNSCAT -- Fingerprinting of Direct Tunnelling
					if (|(find_all(c$dns$query, /dnscat/))| == 1) {
						Log::write(TUNNELLING::LOG, [$evt="DNSCAT Detected", $ts=network_time(), $id=c$id, $data=c$dns$query]);
						if (direct_suppression[0] == 5) {
							print fmt("Fingerprinted! DNSCAT Detected -- Attacking IP: %s | Victim IP: %s . Console Suppression for 10secs.", c$id$resp_h, c$id$orig_h);	
							direct_suppression[0] += 1;
						} else if (direct_suppression[0] > 5) {
							return;
						} else {
							print fmt("Fingerprinted! DNSCAT Detected -- Attacking IP: %s | Victim IP: %s", c$id$resp_h, c$id$orig_h);
							direct_suppression[0] += 1;
						}
					}
					#DNS2TCP -- Failed attempt to Fingerprint. Needs work.
					else if (|(find_all(c$dns$query, /dn8AAAA/))| == 1) {
						Log::write(TUNNELLING::LOG, [$evt="DNS2TCP Detected", $ts=network_time(), $id=c$id, $data=c$dns$query]);
						if (direct_suppression[1] == 5) {
							print fmt("Fingerprinted! DNS2TCP Detected -- Attacking IP: %s | Victim IP: %s . Console Suppression for 10secs.", c$id$resp_h, c$id$orig_h);	
							direct_suppression[1] += 1;
						} else if (direct_suppression[1] > 5) {
							return;
						} else {
							print fmt("Fingreprinted! DNS2TCP Detected -- Attacking IP: %s | Victim IP: %s", c$id$resp_h, c$id$orig_h);							
							direct_suppression[1] += 1;
						}
					}
					#Unable to Fingerprint
					else {
						Log::write(TUNNELLING::LOG, [$evt="Suspect DNS Detected", $ts=network_time(), $id=c$id, $data="DNS not in Whitelist. Unable to Fingerprint."]);	
						if (direct_suppression[2] == 5) {
							print fmt("SUSPECT DNS: %s . Console Suppression for 10secs.", c$id$resp_h);
							direct_suppression[2] += 1;
						} else if (direct_suppression[2] > 5) {
							return;
						} else {
							print fmt("SUSPECT DNS: %s", c$id$resp_h);
							direct_suppression[2] += 1;
						}
					}
				}
				else {
					Log::write(TUNNELLING::LOG, [$evt="Suspect DNS Detected", $ts=network_time(), $id=c$id, $data="DNS not in Whitelist. Unable to Fingerprint."]);	
					if (direct_suppression[3] == 5) {
						print fmt("SUSPECT DNS: %s . Console Suppression for 10secs.", c$id$resp_h);
						direct_suppression[3] += 1;
					} else if (direct_suppression[3] > 5) {
						return;
					} else {
						print fmt("SUSPECT DNS: %s", c$id$resp_h);
						direct_suppression[3] += 1;
					}				
				}
			}
			else {
				Log::write(TUNNELLING::LOG, [$evt="Suspect DNS Detected", $ts=network_time(), $id=c$id, $data="DNS not in Whitelist. Unable to Fingerprint."]);	
				if (direct_suppression[4] == 5) {
					print fmt("SUSPECT DNS: %s . Console Suppression for 10secs.", c$id$resp_h);
					direct_suppression[4] += 1;
				} else if (direct_suppression[4] > 5) {
					return;
				} else {
					print fmt("SUSPECT DNS: %s", c$id$resp_h);
					direct_suppression[4] += 1;
				}			
			}
		} 
	}
}
