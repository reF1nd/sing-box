
function Test(outbounds, now_selected) {
    var requests = new Array();

    for (var i = 0; i < outbounds.length; i++) {
        requests.push({
            detour: outbounds[i]
        });
    }

    urltests(requests);

    return { value: now_selected };
}
