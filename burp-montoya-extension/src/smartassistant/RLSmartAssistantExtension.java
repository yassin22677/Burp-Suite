import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;

public class RLSmartAssistantExtension implements BurpExtension {

    private Registration proxyReqReg;
    private Registration proxyRespReg;
    private Registration auditIssueReg;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("RL Smart Assistant");

        String base = System.getenv("BURP_RL_API_BASE");
        if (base == null || base.isBlank()) {
            base = "http://127.0.0.1:5000";
        }
        base = base.trim();
        if (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }

        RLHttpClient rlClient = new RLHttpClient(
                base,
                base + "/decide-action",
                base + "/update-reward",
                base + "/api/rl-events"
        );
        RlBurpContext.apply(api, rlClient);

        RLConfigApplier applier = new RLConfigApplier(api, rlClient);

        ProxyToRLActionsHandler proxyHandler = new ProxyToRLActionsHandler(api, rlClient, applier);
        proxyReqReg = api.proxy().registerRequestHandler(proxyHandler);
        proxyRespReg = api.proxy().registerResponseHandler(proxyHandler);

        auditIssueReg = api.scanner().registerAuditIssueHandler(
                ScannerFeedbackHandler.asAuditIssueHandler(api, rlClient)
        );

        String line = "[RL] Loaded. Proxy+Scanner handlers registered.";
        api.logging().logToOutput(line);
        rlClient.sendLog("INFO", line);
    }
}
