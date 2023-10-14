// From https://github.com/lmc999/RegionRestrictionCheck

function Test(outbounds, now_selected) {
    var requests = new Array();

    for (var i = 0; i < outbounds.length; i++) {
        requests.push({
            method: "GET",
            url: "https://www.youtube.com/premium",
            headers: {
                "Host": "www.youtube.com",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.60",
                "Accept-Language": "en",
            },
            cookies: {
                "YSC": "BiCUU3-5Gdk",
                "CONSENT": "YES+cb.20220301-11-p0.en+FX+700",
                "GPS": "1",
                "VISITOR_INFO1_LIVE": "4VwPMkB7W5A",
                "PREF": "tz=Asia.Shanghai",
                "_gcl_au": "1.1.1809531354.1646633279",
            },
            detour: outbounds[i]
        });
    }

    var result = http_requests(requests);

    if (typeof result.error === 'string' && result.error != "") {
        return { error: result.error };
    }

    log_debug("http requests success");

    var responses = result.value;
    var selected = null;
    var min_cost = 0;

    for (var i = 0; i < responses.length; i++) {
        var result = responses[i];
        if (result.error !== null && typeof result.error == 'string' && result.error !== "") {
            log_error("detour: [" + outbounds[i] + "], error: [" + result.error + "]");
        } else {
            var isCN = true;
            if (result.status === 200 && result.body !== "" && result.body.search("www.google.cn") < 0) {
                isCN = false;
                if (min_cost === 0 || result.cost < min_cost) {
                    selected = outbounds[i];
                    min_cost = result.cost;
                }
            }
            log_debug("detour: [" + outbounds[i] + "], status: [" + result.status + "], cn: ["+isCN+"], cost: [" + result.cost + "ms]")
        }
    }

    if (selected == null) {
        return { error: "no outbound is available" };
    }

    return { value: selected };
}
