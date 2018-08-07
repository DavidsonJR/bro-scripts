module TUNNELLING;

event dns_message (c: connection, is_orig: bool, msg: dns_msg, len: count) {
	local elements = split_string(query, /\./);
}
