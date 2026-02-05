import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.http.*;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;

public class ProxyToRLActionsHandler
        implements ProxyRequestHandler, ProxyResponseHandler {

    private static final AtomicLong REQUEST_ID_GEN = new AtomicLong(0);
    private static final AtomicLong ACTION_ID_GEN  = new AtomicLong(0);

    private final MontoyaApi api;
    private final RLHttpClient rlClient;
    private final RLConfigApplier applier;

    public ProxyToRLActionsHandler(
            MontoyaApi api,
            RLHttpClient rlClient,
            RLConfigApplier applier
    ) {
        this.api = api;
        this.rlClient = rlClient;
        this.applier = applier;
    }

    // =========================
    // REQUEST
    // =========================
    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest req) {

        long requestId = REQUEST_ID_GEN.incrementAndGet();
        long actionId  = ACTION_ID_GEN.incrementAndGet();
        String ts      = Instant.now().toString();

        String method = req.method();
        String url    = req.url();

        String lineREQ =
                "[RL][REQ][ts=" + ts + "][reqId=" + requestId + "] "
                        + method + " " + url;

        api.logging().logToOutput(lineREQ);
        rlClient.sendLog("REQ", lineREQ);

        int action = rlClient.decideAction(
                method,
                url,
                url.length(),
                -1
        );

        String lineACT =
                "[RL][ACT][ts=" + ts + "][actionId=" + actionId + "] value=" + action;

        api.logging().logToOutput(lineACT);
        rlClient.sendLog("ACT", lineACT);

        // APPLY is logged + mirrored inside RLConfigApplier
        applier.applyAction(action, url, actionId);

        return ProxyRequestReceivedAction.continueWith(req);
    }

    // =========================
    // RESPONSE
    // =========================
    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse resp) {

        int status = resp.statusCode();
        int reward = (status >= 500) ? -3 : (status >= 400 ? -1 : 0);

        rlClient.sendReward(reward);

        String lineRESP = "[RL][RESP] status=" + status + " reward=" + reward;

        api.logging().logToOutput(lineRESP);
        rlClient.sendLog("RESP", lineRESP);

        return ProxyResponseReceivedAction.continueWith(resp);
    }

    // =========================
    // UNUSED
    // =========================
    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest req) {
        return ProxyRequestToBeSentAction.continueWith(req);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse resp) {
        return ProxyResponseToBeSentAction.continueWith(resp);
    }
}
