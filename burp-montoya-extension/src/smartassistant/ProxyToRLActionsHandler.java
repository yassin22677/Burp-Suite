import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.http.InterceptedRequest;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;

public class ProxyToRLActionsHandler implements ProxyRequestHandler, ProxyResponseHandler {

    private final MontoyaApi api;
    private final RLHttpClient rlClient;
    private final RLConfigApplier applier;

    public ProxyToRLActionsHandler(MontoyaApi api, RLHttpClient rlClient, RLConfigApplier applier) {
        this.api = api;
        this.rlClient = rlClient;
        this.applier = applier;
    }

    // ---------------------------
    // REQUEST path
    // ---------------------------
    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest req) {

        // Example: only act on in-scope traffic (common in pentesting)
        if (!req.isInScope()) {
            return ProxyRequestReceivedAction.continueWith(req);
        }

        // Build a simple "state"
        String method = req.method();
        String url = req.url();
        int urlLen = url.length();

        // Ask RL for an action
        int actionId = rlClient.decideAction(method, url, urlLen, -1);

        // Apply tuning action in Burp
        applier.applyAction(actionId, url);

        api.logging().logToOutput("[RL][REQ] action=" + actionId + " " + method + " " + url);

        // You can also implement drop/intercept based on actionId (optional)
        return ProxyRequestReceivedAction.continueWith(req);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest req) {
        return ProxyRequestToBeSentAction.continueWith(req);
    }

    // ---------------------------
    // RESPONSE path
    // ---------------------------
    @Override
    public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse resp) {

        // We can use responses for better state and reward shaping
        int status = resp.statusCode();

        // Very simple reward example:
        // - 2xx/3xx: neutral
        // - 4xx: slightly negative (might be noise/blocked)
        // - 5xx: negative (server errors / instability)
        int reward = (status >= 500) ? -3 : (status >= 400 ? -1 : 0);

        rlClient.sendReward(reward);

        api.logging().logToOutput("[RL][RESP] status=" + status + " reward=" + reward);

        return ProxyResponseReceivedAction.continueWith(resp);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse resp) {
        return ProxyResponseToBeSentAction.continueWith(resp);
    }
}
