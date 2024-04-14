module PacketAnalyzer::ETHERNET;

export {
    const default_analyzer: PacketAnalyzer::Tag = PacketAnalyzer::ANALYZER_IP &redef;
    global snap_analyzer: PacketAnalyzer::Tag &redef;
    global novell_raw_analyzer: PacketAnalyzer::Tag &redef;
    global llc_analyzer: PacketAnalyzer::Tag &redef;
}
event zeek_init() &priority=20 {
    PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERNET, 0x8847, PacketAnalyzer::ANALYZER_MPLS);
    PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERNET, 0x0800, PacketAnalyzer::ANALYZER_IP);
    PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_ETHERNET, 0x86DD, PacketAnalyzer::ANALYZER_IP);
    PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_IP, 0x06, PacketAnalyzer::ANALYZER_TCP);
    PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_IP, 0x11, PacketAnalyzer::ANALYZER_UDP);
    PacketAnalyzer::register_packet_analyzer(PacketAnalyzer::ANALYZER_IP, 0x01, PacketAnalyzer::ANALYZER_ICMP);
}

#Detecting HTTP requests and replies
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    print fmt("HTTP request from %s: %s %s", c$id$orig_h, method, original_URI);
}
event http_reply(c: connection, version: string, code: count, reason: string) {
    print fmt("HTTP reply from %s: %s %s", c$id$resp_h, code, reason);
}

#Detecting malicious IPs
type Idx: record {
    ip: string &optional;
};

global malicious_ips: set[string] = {};

event bro_init() {
    Input::add_table([$source="malicious_data/malicious_ips.txt", $name="MaliciousIPs", $idx=Idx, $destination=malicious_ips]);
}

event new_connection(c: connection) {
    if (fmt("%s", c$id$orig_h) in malicious_ips || fmt("%s", c$id$resp_h) in malicious_ips) {
        print fmt("Malicious connection detected: %s", c$id);
    }
}

#Detecting suspicious user agents
type Idx: record {
    user_agent: string &optional;
};
global suspicious_user_agents: set[string];

event bro_init()
    {
    Input::add_table([$source="malicious_data/suspicious_http_user_agents_list.csv", $name="SuspiciousUserAgents", $idx=Idx, $destination=suspicious_user_agents]);
    }

event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if (name == "User-Agent" && value in suspicious_user_agents) {
        print fmt("Suspicious User-Agent detected: %s", value);
    }
}

#Detecting port scans
global syn_sent: table[addr] of count = table();
global syn_ack: table[addr] of count = table();

event connection_attempt(c: connection) {
    if ( c$id$orig_h in syn_sent ) {
        ++syn_sent[c$id$orig_h];
    } else {
        syn_sent[c$id$orig_h] = 1;
    }
}
event connection_established(c: connection) {
    if ( c$id$orig_h in syn_ack ) {
        ++syn_ack[c$id$orig_h];
    } else {
        syn_ack[c$id$orig_h] = 1;
    }
}
event zeek_done() {
    for (address in syn_sent) {
        if (!(address in syn_ack) || syn_sent[address] / syn_ack[address] > 3) {
            print fmt("Possible port scan from %s", address);
        }
    }
}

#Detecting DoS attacks
@load base/frameworks/input
@load base/protocols/conn

global conn_count: table[addr] of count = table();

event new_connection(c: connection) {
    if (c$id$orig_h in conn_count) {
        ++conn_count[c$id$orig_h];
    } else {
        conn_count[c$id$orig_h] = 1;
    }
}
event connection_state_remove(c: connection) {
    if (conn_count[c$id$orig_h] > 1000) {  # Adjust this threshold as needed
        print fmt("Possible DoS attack involving %s", c$id$orig_h);
        delete conn_count[c$id$orig_h];
    }
}

#Detecting suspicious DNS queries
@load base/protocols/conn
@load base/protocols/dns

type Idx: record {
    domain: string &log;
};

global suspicious_domains: set[string] = {};

event bro_init() {
    Input::add_table([$source="malicious_data/suspicious_domains.txt", $name="suspicious_domains", $idx=Idx, $destination=suspicious_domains]);
}

global connection_count: table[addr] of count = table();

event new_connection(c: connection) {
    if ( c$id$resp_p == 53/tcp ) {
        if ( c$id$orig_h in connection_count ) {
            ++connection_count[c$id$orig_h];
        } else {
            connection_count[c$id$orig_h] = 1;
        }
    }
}

event connection_state_remove(c: connection) {
    if ( c$id$orig_h in connection_count && connection_count[c$id$orig_h] > 10 ) {
        print fmt("More than 10 connections from %s", c$id$orig_h);
    }
}

redef ignore_checksums = T;
redef Log::default_rotation_dir = "logs";


