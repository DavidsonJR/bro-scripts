# This module is used to detect base64 encoded TXT records which hold malicious payloads. This is done by 
# attempting to decode the encoded strings and match for keywords such as PowerShell.
# This module will not be able to detect keywords that are broken-up or split across multiple strings.
#
# Written by Stephan Davidson and Ferdous Saljooki

@load base/frameworks/sumstats

module TXT;

const scripting_languages = /veil|python|powershell/ &redef;
const base_64_string = /^[a-zA-Z0-9\/"$+.]*={0,2}$/ &redef;

event dns_TXT_reply(c: connection, msg: dns_msg, ans: dns_answer, strs: string_vec) {
	SumStats::observe("dns.observe", [$host=c$id$orig_h], [$str=c$dns$query]);
    	if (r_queries != 0) {
		Log::write(TXT::LOG, [$evt="Excessive TXT Queries", $ts=network_time(), $id=c$id, $data=fmt("Queries: %.0f. %d are unique", r_queries, r_unique)]);
		r_unique = 0;
		r_queries = 0;
    	}

    	local txt_str0 = split_string(c$dns$answers[0], / /); #TXT Data
    	txt_str0[0] = "";
    	txt_str0[1] = "";
    	local txt_str = join_string_vec(txt_str0, "");
    	local txt_len = |txt_str|; #Length of the TXT Record as INT
    	local base_64 = match_pattern(txt_str, base_64_string);
	
	if (base_64$matched == T) {
		if (!("==" in txt_str)) {
	    		while ((txt_len % 8) != 0) { #Pads the string to 8 byte boundry for base64 decoding
            			txt_str += "0";
	    			txt_len += 1;
			}
  	    	}
	    local s1 = decode_base64(txt_str); #Base64 decodes the string (attempts, regardless of encoding)
	    local s2 = to_string_literal(s1); #Coverts String to literal string (changes hex values to string)
            local s3 = split_string(s2, /\\x[a-fA-F0-9]{2}/); #splits the string into chars
	    local s4 = join_string_vec(s3, ""); #removes the split (weird but whatever)

	    if (scripting_languages in to_lower(s4)) {
	        Log::write(TXT::LOG, [$evt="Malicious Keyword Match Detected", $ts=network_time(), $id=c$id, $data=s4]);	    
	    	print fmt("%s has generate a keyword match: %s", c$id$orig_h, s4);
	    }
	    else {
	    	Log::write(TXT::LOG, [$evt="Base64 TXT Record Detected", $ts=network_time(), $id=c$id, $data=txt_str]);
	    	print fmt("Base64 Detected: %s", txt_str);
	    }
	} else {
		if (scripting_languages in to_lower(txt_str)) {
	        	Log::write(TXT::LOG, [$evt="Malicious Keyword Match Detected", $ts=network_time(), $id=c$id, $data=s4]);	    
	    		print fmt("%s has generate a keyword match: %s", c$id$orig_h, txt_str);
	    	}
	}
}
