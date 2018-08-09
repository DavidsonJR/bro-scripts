@load base/frameworks/sumstats

module TXT;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		evt: string &log;
		ts: time &log;
		id: conn_id &log;
		data: string &log;
	};
}

const excessive_limit: double = 15  &redef;
const time_interval = 30 secs &redef;

global r_queries = 0.0;
global r_unique = 0;

event bro_init() {
    Log::create_stream(TXT::LOG, [$columns=Info, $path="/opt/bro/spool/manager/capstone_txt"]);

    local r1 = SumStats::Reducer($stream="dns.observe", $apply=set(SumStats::SUM, SumStats::HLL_UNIQUE));

    SumStats::create([$name="dns.queries",
                      $epoch = time_interval,
                      $threshold = excessive_limit,
                      $reducers=set(r1),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                      	{
                        return result["dns.observe"]$sum;
                      	},
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                      	{
                        	local r = result["dns.observe"];
                          	print fmt("%s has made more than %.0f DNS queries and %d unique DNS queries.", key$host, r$sum, r$hll_unique);
				r_queries = r$sum;
				r_unique = r$hll_unique;
                      	}
                    ]);
    }
