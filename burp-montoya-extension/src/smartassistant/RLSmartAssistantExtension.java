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

        // 1) RL HTTP client (Python API)
        RLHttpClient rlClient = new RLHttpClient(
                "http://127.0.0.1:5000/decide-action",
                "http://127.0.0.1:5000/update-reward"
        );

        // 2) Apply actions to Burp
        RLConfigApplier applier = new RLConfigApplier(api);

        // 3) Proxy handlers
        ProxyToRLActionsHandler proxyHandler = new ProxyToRLActionsHandler(api, rlClient, applier);
        proxyReqReg = api.proxy().registerRequestHandler(proxyHandler);
        proxyRespReg = api.proxy().registerResponseHandler(proxyHandler);

        // 4) Scanner feedback handler (rewards from Burp Scanner issues)
        auditIssueReg = api.scanner().registerAuditIssueHandler(
                ScannerFeedbackHandler.asAuditIssueHandler(api, rlClient)
        );

        api.logging().logToOutput("[RL] Loaded. Proxy+Scanner handlers registered.");
    }
}
