import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.http.*;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

public class ProxyToRLActionsHandler
        implements ProxyRequestHandler, ProxyResponseHandler {

    private static final AtomicLong REQUEST_ID_GEN = new AtomicLong(0);
    private static final AtomicLong ACTION_ID_GEN  = new AtomicLong(0);

    private final MontoyaApi api;
    private final RLHttpClient rlClient;
    private final RLConfigApplier applier;

    // Keep request context until response
    private final Map<Long, RequestCtx> ctxMap = new ConcurrentHashMap<>();

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

        api.logging().logToOutput(
                "[RL][REQ][ts=" + ts + "][reqId=" + requestId + "] "
                        + method + " " + url
        );

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

        // Save context for response
        ctxMap.put(
                requestId,
                new RequestCtx(
                        requestId,
                        actionId,
                        action,
                        method,
                        url
                )
        );

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

        api.logging().logToOutput(
                "[RL][RESP] status=" + status + " reward=" + reward
        );

        // Match ONE pending request (same behavior as your logs)
        ctxMap.values().stream().findFirst().ifPresent(ctx -> {

            String json =
                    "{"
                            + "\"request_id\":" + ctx.requestId + ","
                            + "\"action_id\":" + ctx.actionId + ","
                            + "\"action_name\":\"" + ctx.action + "\","
                            + "\"url\":\"" + ctx.url + "\","
                            + "\"http_method\":\"" + ctx.method + "\","
                            + "\"status_code\":" + status + ","
                            + "\"reward\":" + reward + ","
                            + "\"explanation\":\"RL decision based on traffic behavior\""
                            + "}";

            // 🔴 THIS is the DB logging point
            rlClient.postJson("http://127.0.0.1:5000/api/rl-events", json);

            ctxMap.remove(ctx.requestId);
        });

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

    // =========================
    // INTERNAL CONTEXT
    // =========================
    private static class RequestCtx {
        long requestId;
        long actionId;
        int action;
        String method;
        String url;

        RequestCtx(long requestId,
                   long actionId,
                   int action,
                   String method,
                   String url) {
            this.requestId = requestId;
            this.actionId  = actionId;
            this.action    = action;
            this.method    = method;
            this.url       = url;
        }
    }
}
