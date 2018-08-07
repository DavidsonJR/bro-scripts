global request_size = 0;
global response_size = 0;

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
    }
    if (string_size > 17) {
        print fmt("Reqest: %d characters in a subdomain", string_size);
        if ((string_size == 146) && (request_size == 0)) {
            request_size = string_size;
        }
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
    }
    if (string_size > 17) {
        print fmt("TXT Response: %d characters in a subdomain", string_size);
        if ((request_size == 146) && (response_size == 0) && (string_size == 82)) {
            response_size = string_size;
        }
        else if ((request_size == 146) && (response_size == 82) && (string_size == 34)) { 
            print fmt("DNSCAT2 Detected! Beacon out.");
        }
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
    }
    if (string_size > 17) {
        print fmt("CNAME Response: %d characters in a subdomain", string_size);
        if ((request_size == 146) && (response_size == 0) && (string_size == 82)) {
            response_size = string_size;
        }
        else if ((request_size == 146) && (response_size == 82) && (string_size == 34)) { 
            print fmt("DNSCAT2 Detected! Beacon out.");
        }
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
    }
    if (string_size > 17) {
        print fmt("MX Response: %d characters in a subdomain", string_size);
        if ((request_size == 146) && (response_size == 0) && (string_size == 82)) {
            response_size = string_size;
        }
        else if ((request_size == 146) && (response_size == 82) && (string_size == 34)) { 
            print fmt("DNSCAT2 Detected! Beacon out.");
        }   
    }
}
