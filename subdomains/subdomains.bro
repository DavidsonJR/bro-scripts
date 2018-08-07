const dns_ports_allowed = set(53/udp, 53/tcp, 5353/udp, 5355/udp);
const blacklist_tld = set("country", "stream", "download", "xin", "gdn", "racing", "jetzt", "win", "bid", "vip", "ren", "kim", "loan", "mom", "party", "review", "trade", "date", "wang", "accountants", "zip", "cricket", "science", "work", "gq", "link");
const ignore_sub_domains = set("www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "log", "ssl", "us", "apis", "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test", "portal", "ns", "ww1", "host", "finance", "support", "dev", "web", "bbs", "ww42", "mx", "email", "cloud", "1", "mail1", "2", "forum", "owa", "www2", "gw", "admin", "store", "mx1", "cdn", "api", "exchange", "app", "gov", "vps", "news");
const ignore_domains = set("google.com", "microsoft.com", "yahoo.com", "amazon.com", "dropbox.com", "avg.com", "msn.com", "youtube.com", "ip6.arpa");

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {

    if (!(c$id$resp_p in dns_ports_allowed)) {
        return;
    }

    if (!(c?$dns)) {
        return;
    }

    if (!(c$dns?$query)) {
        return;
    }

    local domain: string;
    local sub_domain: set[string];
    local split_domain: vector of string;

    split_domain = vector();
    split_domain = split_string(c$dns$query, /\./);

    if (|split_domain| >= 2) {
        domain = split_domain[|split_domain|-2] + "." + split_domain[|split_domain|-1];
        if (domain in ignore_domains) {
            return;
        }
    }

    for (x in split_domain) {
        if (!(split_domain[x] in ignore_sub_domains) && (split_domain[x] != split_domain[|split_domain|-1]) && (split_domain[x] != split_domain[|split_domain|-2])) {
            add sub_domain[split_domain[x]];
        }
    }

    if (|sub_domain| >= 3) {
        print fmt("Excessive Unknown Subdomains Detected - %s", c$dns$query);
    }

    if (split_domain[|split_domain|-1] in blacklist_tld) {
        print fmt("Blacklisted TLD Detected - %s", c$dns$query);
    }
}
