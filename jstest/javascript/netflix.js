// From https://github.com/lmc999/RegionRestrictionCheck

function Test(outbounds, now_selected) {
    var requests = new Array();

    for (var i = 0; i < outbounds.length; i++) {
        requests.push({
            method: "GET",
            url: "https://www.netflix.com/title/81280792",
            headers: {
                "Host": "www.netflix.com",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.60",
            },
            detour: outbounds[i]
        });
    }
    for (var i = 0; i < outbounds.length; i++) {
        requests.push({
            method: "GET",
            url: "https://www.netflix.com/title/70143836",
            headers: {
                "Host": "www.netflix.com",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.60",
            },
            detour: outbounds[i]
        });
    }
    for (var i = 0; i < outbounds.length; i++) {
        requests.push({
            method: "GET",
            url: "https://www.netflix.com/title/80018499",
            headers: {
                "Host": "www.netflix.com",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.60",
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

    for (var i = 0; i < outbounds.length; i++) {
        var result1 = responses[i];
        var result2 = responses[i + outbounds.length];
        var result3 = responses[i + outbounds.length * 2];
        if ((result1.error !== null && typeof result1.error == 'string' && result1.error !== "") || (result2.error !== null && typeof result2.error == 'string' && result2.error !== "")) {
            log_error("detour: [" + outbounds[i] + "], error: [" + result1.error + "] [" + result2.error + "]");
        } else {
            var isAllow = false;
            var type = "Failed";
            if (result1.status === 404 && result2.status === 404) {
                type = "Originals Only";
            }
            if (result1.status === 403 && result2.status === 403) {
                type = "Blocked";
            }
            if (result1.status === 200 || result2.status === 200) {
                var tag = false;
                if (result3.headers != undefined) {
                    var u = result3.headers["X-Originating-Url"].toString();
                    if (u !== "") {
                        var cc = u.split('/')[3];
                        if (cc !== "title") {
                            type = cc.split('-')[0].toUpperCase();
                            tag = true;
                        }
                    }
                }
                if (!tag) {
                    type = "Yes";
                }
                isAllow = true;
            }
            if (isAllow) {
                if (min_cost === 0 || (result1.cost + result2.cost) / 2 < min_cost) {
                    selected = outbounds[i];
                    min_cost = (result1.cost + result2.cost) / 2;
                }
            }
            log_debug("detour: [" + outbounds[i] + "], status: [" + result1.status + ", " + result2.status + "], type: [" + type + "], cost: [" + (result1.cost + result2.cost) / 2 + "ms]")
        }
    }

    if (selected == null) {
        return { error: "no outbound is available" };
    }

    return { value: selected };
}