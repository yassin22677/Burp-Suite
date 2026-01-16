import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;

public class RLConfigApplier {

    private final MontoyaApi api;

    public RLConfigApplier(MontoyaApi api) {
        this.api = api;
    }

    /**
     * Action mapping (you can change this later):
     * 0 = do nothing
     * 1 = enable proxy intercept
     * 2 = disable proxy intercept
     * 3 = start passive audit (built-in)
     * 4 = start active audit (built-in)
     */
    public void applyAction(int actionId, String url) {
        switch (actionId) {
            case 0 -> {
                // no-op
            }
            case 1 -> api.proxy().enableIntercept();
            case 2 -> api.proxy().disableIntercept();

            case 3 -> {
                // Start passive audit using built-in configuration
                AuditConfiguration cfg = AuditConfiguration.auditConfiguration(
                        BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS
                );
                api.scanner().startAudit(cfg);
                api.logging().logToOutput("[RL] Started PASSIVE audit (built-in) for: " + url);
            }

            case 4 -> {
                // Start active audit using built-in configuration
                AuditConfiguration cfg = AuditConfiguration.auditConfiguration(
                        BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS
                );
                api.scanner().startAudit(cfg);
                api.logging().logToOutput("[RL] Started ACTIVE audit (built-in) for: " + url);
            }

            default -> api.logging().logToError("[RL] Unknown actionId=" + actionId);
        }
    }
}
