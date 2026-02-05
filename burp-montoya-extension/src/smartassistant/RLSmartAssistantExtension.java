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

        // IMPORTANT: keep decide/reward separate + add logs endpoint
        RLHttpClient rlClient = new RLHttpClient(
                "http://127.0.0.1:5000/decide-action",
                "http://127.0.0.1:5000/update-reward",
                "http://127.0.0.1:5000/api/rl-events"
        );

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
