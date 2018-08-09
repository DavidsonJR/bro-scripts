# This module is designed to detect malicious tunnelling through DNS. In its current state, it's also able to fully
# fingerprint DNSCAT2.
#
# Authors: Stephan Davidson and Ferdous Saljooki

module TUNNELLING;

global nums: table[int] of count &default=0 &write_expire=15secs;

event dns_request (c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
	local elements = split_string(c$dns$query, /\./);
	local size_of_elements = 0;
	local string_size = 0;
	for (i in elements) {
		size_of_elements = size_of_elements + 1;
	}
	if (size_of_elements > 2) {
		for (i in elements) {
			if (i < (size_of_elements - 2)) {
				string_size = (string_size + |elements[i]|);
			}
		}
	} else {
		return;
	}
	if (string_size > 17) {
		if ((string_size == 146) && (nums[0] == 0)) {
			nums[0] = string_size;
		} else if ((string_size == 34) && (nums[2] == 1)) {
			nums[2] = 1;
		}
	} else {
		return;
	}
}

event dns_TXT_reply(c: connection, msg: dns_msg, ans: dns_answer, strs: vector of string) {
	local elements = split_string(c$dns$query, /\./);
	local size_of_elements = 0;
	local string_size = 0;
	for (i in elements) {
		size_of_elements = size_of_elements + 1;
	}
	if (size_of_elements > 2) {
		for (i in elements) {
			if (i < (size_of_elements - 2)) {
				string_size = (string_size + |elements[i]|);
			}
		}
	} else {
		return;
	}
	if (string_size > 17) {
		if ((nums[0] == 146) && (nums[1] == 0) && (string_size == 82)) {
			nums[1] = string_size;
		} else if ((nums[0] == 146) && (nums[1] == 82) && (string_size == 34)) {
			print fmt("DNSCAT2 TUNNELLING Detected! Beacon out.");
			Log::write(TUNNELLING::LOG, [$evt="DNSCAT2 Detected", $ts=network_time(), $id=c$id, $data=c$dns$query]);
			nums[0] = 0;
			nums[1] = 0;
			nums[2] = 1;
		} else if (!(nums[2] == 1)) {
			print fmt("SUSPECTED TUNNELLING -- TXT Response: %d characters in a subdomain", string_size);
			Log::write(TUNNELLING::LOG, [$evt="SUSPECTED TUNNELLING -- TXT", $ts=network_time(), $id=c$id, $data=c$dns$query]);
		}
	} else {
		return;
	}
}

event dns_CNAME_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string) {
	local elements = split_string(c$dns$query, /\./);
	local size_of_elements = 0;
	local string_size = 0;
	for (i in elements) {
		size_of_elements = size_of_elements + 1;
	}
	if (size_of_elements > 2) {
		for (i in elements) {
			if (i < (size_of_elements - 2)) {
				string_size = (string_size + |elements[i]|);
			}
		}
	} else {
		return;
	}
	if (string_size > 17) {
		if ((nums[0] == 146) && (nums[1] == 0) && (string_size == 82)) {
			nums[1] = string_size;
		} else if ((nums[0] == 146) && (nums[1] == 82) && (string_size == 34)) {
			print fmt("DNSCAT2 TUNNELLING Detected! Beacon out.");
			Log::write(TUNNELLING::LOG, [$evt="DNSCAT2 Detected", $ts=network_time(), $id=c$id, $data=c$dns$query]);
			nums[0] = 0;
			nums[1] = 0;
			nums[2] = 1;
		} else if (!(nums[2] == 1)) {
			print fmt("SUSPECTED TUNNELLING -- CNAME Response: %d characters in a subdomain", string_size);
			Log::write(TUNNELLING::LOG, [$evt="SUSPECTED TUNNELLING -- CNAME", $ts=network_time(), $id=c$id, $data=c$dns$query]);
		}
	} else {
		return;
	}
}

event dns_MX_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string, preference: count) {
	local elements = split_string(c$dns$query, /\./);
	local size_of_elements = 0;
	local string_size = 0;
	for (i in elements) {
		size_of_elements = size_of_elements + 1;
	}
	if (size_of_elements > 2) {
		for (i in elements) {
			if (i < (size_of_elements - 2)) {
				string_size = (string_size + |elements[i]|);
			}
		}
	} else {
		return;
	}
	if (string_size > 17) {
		if ((nums[0] == 146) && (nums[1] == 0) && (string_size == 82)) {
			nums[1] = string_size;
		} else if ((nums[0] == 146) && (nums[1] == 82) && (string_size == 34)) {
			print fmt("DNSCAT2 TUNNELLING Detected! Beacon out.");
			Log::write(TUNNELLING::LOG, [$evt="DNSCAT2 Detected", $ts=network_time(), $id=c$id, $data=c$dns$query]);
			nums[0] = 0;
			nums[1] = 0;
			nums[2] = 1;
		} else if (!(nums[2] == 1)) {
			print fmt("SUSPECTED TUNNELLING -- MX Response: %d characters in a subdomain", string_size);
			Log::write(TUNNELLING::LOG, [$evt="SUSPECTED TUNNELLING -- MX", $ts=network_time(), $id=c$id, $data=c$dns$query]);
		}
	} else {
		return;
	}
}
