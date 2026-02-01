import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.http.*;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

public class ProxyToRLActionsHandler
        implements ProxyRequestHandler, ProxyResponseHandler {

    private final MontoyaApi api;
    private final RLHttpClient rlClient;
    private final RLConfigApplier applier;

    // ---- ID generators (timeline traceability)
    private static final AtomicLong REQUEST_ID = new AtomicLong(0);
    private static final AtomicLong ACTION_ID = new AtomicLong(0);
    private static final AtomicLong RESPONSE_ID = new AtomicLong(0);

    // ---- Bootstrap: first time per host
    private final Set<String> seenHosts = new HashSet<>();

    public ProxyToRLActionsHandler(
            MontoyaApi api,
            RLHttpClient rlClient,
            RLConfigApplier applier
    ) {
        this.api = api;
        this.rlClient = rlClient;
        this.applier = applier;
    }

    // ================= REQUEST =================
    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest req) {

        if (!req.isInScope()) {
            return ProxyRequestReceivedAction.continueWith(req);
        }

        String ts = Instant.now().toString();
        long reqId = REQUEST_ID.incrementAndGet();

        String method = req.method();
        String url = req.url();
        String host = req.httpService().host();

        api.logging().logToOutput(
                "[RL][REQ][ts=" + ts + "][reqId=" + reqId + "] " + method + " " + url
        );

        // -------- BOOTSTRAP (first request per host)
        if (!seenHosts.contains(host)) {
            seenHosts.add(host);

            long actionId = ACTION_ID.incrementAndGet();
            int action = 3; // PASSIVE_SCAN

            api.logging().logToOutput(
                    "[RL][BOOTSTRAP][ts=" + ts + "][actionId=" + actionId + "] PASSIVE_SCAN"
            );

            applier.applyAction(action, url, actionId);
            return ProxyRequestReceivedAction.continueWith(req);
        }

        // -------- RL DECISION
        int action = rlClient.decideAction(method, url, url.length(), -1);
        long actionId = ACTION_ID.incrementAndGet();

        api.logging().logToOutput(
                "[RL][ACT][ts=" + ts + "][actionId=" + actionId + "] value=" + action
        );

        applier.applyAction(action, url, actionId);

        return ProxyRequestReceivedAction.continueWith(req);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest req) {
        return ProxyRequestToBeSentAction.continueWith(req);
    }

    // ================= RESPONSE =================
    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse resp) {

        String ts = Instant.now().toString();
        long respId = RESPONSE_ID.incrementAndGet();
        int status = resp.statusCode();

        int reward = (status >= 500) ? -3 :
                     (status >= 400) ? -1 : 0;

        rlClient.sendReward(reward);

        api.logging().logToOutput(
                "[RL][RESP][ts=" + ts + "][respId=" + respId + "] status=" + status + " reward=" + reward
        );

        return ProxyResponseReceivedAction.continueWith(resp);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse resp) {
        return ProxyResponseToBeSentAction.continueWith(resp);
    }
}
