// From https://github.com/lmc999/RegionRestrictionCheck

function Test(outbounds, now_selected) {
    var requests = new Array();

    for (var i = 0; i < outbounds.length; i++) {
        requests.push({
            method: "GET",
            url: "https://chat.openai.com",
            headers: {
                "Host": "chat.openai.com",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.60",
                "Accept-Language": "en",
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
            var isAllow = false;
            if (result.status !== 403 && typeof result.body == 'string' && result.body !== "" && result.body.search("Sorry, you have been blocked") < 0) {
                isAllow = true;
                if (min_cost === 0 || result.cost < min_cost) {
                    selected = outbounds[i];
                    min_cost = result.cost;
                }
            }
            log_debug("detour: [" + outbounds[i] + "], status: [" + result.status + "], isAllow: [" + isAllow + "], cost: [" + result.cost + "ms]")
        }
    }

    if (selected == null) {
        return { error: "no outbound is available" };
    }

    return { value: selected };
}
