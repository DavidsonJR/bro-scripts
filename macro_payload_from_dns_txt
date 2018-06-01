# This rule will detect a DNS reply via TXT records of a base64 (or plain text) 
# payload; most likely initiated via a macro embedded document.
#
# Authored by: Stephan Davidson and Ferdous Saljooki

export {
    redef enum Notice::Type += {
		TXT_Reply,
	};
    const scripting_languages = /veil|python|powershell/ &redef;
}

event dns_TXT_reply(c: connection, msg: dns_msg, ans: dns_answer, strs: string_vec) {
    local txt_str = split_string(c$dns$answers[0], / /)[2]; #TXT Data
    local txt_len = |txt_str|; #Length of the TXT Record as INT
    while ((txt_len % 8) != 0) { #Pads the string to 8 byte boundry for base64 decoding
        txt_str += "0";
	    txt_len += 1;
	}
	
	local s1 = decode_base64(txt_str); #Base64 decodes the string (attempts, regardless of encoding)
	local s2 = to_string_literal(s1); #Coverts String to literal string (changes hex values to string)
    local s3 = split_string(s2, /\\x[a-fA-F0-9]{2}/); #splits the string into chars
	local s4 = join_string_vec(s3, ""); #removes the split (weird but whatever)
		
	if (scripting_languages in to_lower(s4)) {
	    print s4; #IFF one of the scripting languages that we're looking for is found, a message will display.
	}
}
