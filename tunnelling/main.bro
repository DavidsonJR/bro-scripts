module TUNNELLING;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		evt: string &log;
		ts: time &log;
		id: conn_id &log;
		data: string &log;
	};
}

event bro_init() {
	Log::create_stream(FINGERPRINT::LOG, [$columns=Info, $path="/opt/bro/spool/manager/capstone_fingerprint"]);
}
