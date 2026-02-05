import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;

public class RLConfigApplier {

    private final MontoyaApi api;
    private final RLHttpClient rlClient;

    public RLConfigApplier(MontoyaApi api, RLHttpClient rlClient) {
        this.api = api;
        this.rlClient = rlClient;
    }

    public void applyAction(int action, String url, long actionId) {

        String line;

        switch (action) {
            case 0 -> line = "[RL][APPLY][actionId=" + actionId + "] NO_OP";

            case 1 -> {
                api.proxy().enableIntercept();
                line = "[RL][APPLY][actionId=" + actionId + "] ENABLE_INTERCEPT";
            }

            case 2 -> {
                api.proxy().disableIntercept();
                line = "[RL][APPLY][actionId=" + actionId + "] DISABLE_INTERCEPT";
            }

            case 3 -> {
                AuditConfiguration cfg =
                        AuditConfiguration.auditConfiguration(
                                BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS
                        );

                api.scanner().startAudit(cfg);
                line = "[RL][APPLY][actionId=" + actionId + "] PASSIVE_SCAN " + url;
            }

            case 4 -> {
                AuditConfiguration cfg =
                        AuditConfiguration.auditConfiguration(
                                BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS
                        );

                api.scanner().startAudit(cfg);
                line = "[RL][APPLY][actionId=" + actionId + "] ACTIVE_SCAN " + url;
            }

            default -> line = "[RL][APPLY][actionId=" + actionId + "] UNKNOWN_ACTION=" + action;
        }

        api.logging().logToOutput(line);
        rlClient.sendLog("APPLY", line);
    }
}
