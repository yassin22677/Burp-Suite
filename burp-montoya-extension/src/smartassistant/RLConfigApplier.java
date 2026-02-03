import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;

public class RLConfigApplier {

    private final MontoyaApi api;

    public RLConfigApplier(MontoyaApi api) {
        this.api = api;
    }

    /**
     * Action mapping:
     * 0 = NO_OP
     * 1 = enable proxy intercept
     * 2 = disable proxy intercept
     * 3 = start passive audit
     * 4 = start active audit
     */
    public String describeAction(int actionId) {
    return switch (actionId) {
        case 0 -> "NO_OP";
        case 1 -> "ENABLE_INTERCEPT";
        case 2 -> "DISABLE_INTERCEPT";
        case 3 -> "START_PASSIVE_SCAN";
        case 4 -> "START_ACTIVE_SCAN";
        default -> "UNKNOWN_ACTION";
    };
}

    public void applyAction(int action, String url, long actionId) {

        switch (action) {
            case 0 -> {
                api.logging().logToOutput(
                        "[RL][APPLY][actionId=" + actionId + "] NO_OP"
                );
            }

            case 1 -> {
                api.proxy().enableIntercept();
                api.logging().logToOutput(
                        "[RL][APPLY][actionId=" + actionId + "] ENABLE_INTERCEPT"
                );
            }

            case 2 -> {
                api.proxy().disableIntercept();
                api.logging().logToOutput(
                        "[RL][APPLY][actionId=" + actionId + "] DISABLE_INTERCEPT"
                );
            }

            case 3 -> {
                AuditConfiguration cfg =
                        AuditConfiguration.auditConfiguration(
                                BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS
                        );

                api.scanner().startAudit(cfg);
                api.logging().logToOutput(
                        "[RL][APPLY][actionId=" + actionId + "] PASSIVE_SCAN " + url
                );
            }

            case 4 -> {
                AuditConfiguration cfg =
                        AuditConfiguration.auditConfiguration(
                                BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS
                        );

                api.scanner().startAudit(cfg);
                api.logging().logToOutput(
                        "[RL][APPLY][actionId=" + actionId + "] ACTIVE_SCAN " + url
                );
            }

            default -> api.logging().logToError(
                    "[RL][APPLY][actionId=" + actionId + "] UNKNOWN_ACTION=" + action
            );
        }
    }
}
