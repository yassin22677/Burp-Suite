import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.http.*;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;

public class ProxyToRLActionsHandler implements ProxyRequestHandler, ProxyResponseHandler {

    private static final AtomicLong ACTION_ID = new AtomicLong(0);

    private final MontoyaApi api;
    private final RLHttpClient rlClient;
    private final RLConfigApplier applier;

    public ProxyToRLActionsHandler(MontoyaApi api,
                                   RLHttpClient rlClient,
                                   RLConfigApplier applier) {
        this.api = api;
        this.rlClient = rlClient;
        this.applier = applier;
    }

    // =========================
    // REQUEST
    // =========================
    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest req) {

        String ts = Instant.now().toString();
        long actionId = ACTION_ID.incrementAndGet();

        String method = req.method();
        String url = req.url();

        api.logging().logToOutput(
                "[RL][REQ][ts=" + ts + "][reqId=" + actionId + "] "
                        + method + " " + url
        );

        // Ask RL (EXPLORATION happens in Python)
        int action = rlClient.decideAction(
                method,
                url,
                url.length(),
                -1
        );

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

    // =========================
    // RESPONSE
    // =========================
    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse resp) {

        int status = resp.statusCode();
        int reward = (status >= 500) ? -3 : (status >= 400 ? -1 : 0);

        rlClient.sendReward(reward);

        api.logging().logToOutput(
                "[RL][RESP] status=" + status + " reward=" + reward
        );

        return ProxyResponseReceivedAction.continueWith(resp);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse resp) {
        return ProxyResponseToBeSentAction.continueWith(resp);
    }
}
