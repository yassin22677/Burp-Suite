import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.audit.AuditIssueHandler;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.lang.reflect.Method;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;

public class ScannerFeedbackHandler {

    private static final AtomicLong ISSUE_ID_GEN  = new AtomicLong(0);
    private static final AtomicLong REWARD_ID_GEN = new AtomicLong(0);

    public static AuditIssueHandler asAuditIssueHandler(
            MontoyaApi api,
            RLHttpClient rlClient
    ) {
        return new AuditIssueHandler() {

            @Override
            public void handleNewAuditIssue(AuditIssue issue) {

                long issueId = ISSUE_ID_GEN.incrementAndGet();
                String ts = Instant.now().toString();

                int reward = 0;

                // Reward based on severity
                String sev = safeName(issue.severity());
                switch (sev) {
                    case "HIGH" -> reward += 5;
                    case "MEDIUM" -> reward += 3;
                    case "LOW" -> reward += 1;
                    default -> reward += 0;
                }

                // Reward based on confidence
                String conf = safeName(issue.confidence());
                switch (conf) {
                    case "FIRM" -> reward += 2;
                    case "TENTATIVE" -> reward -= 1;
                    default -> reward += 0;
                }

                // URL is NOT available in some Montoya versions -> safe fallback
                String issueUrl = tryGetIssueUrl(issue);

                api.logging().logToOutput(
                        "[RL][SCAN][ts=" + ts + "][issueId=" + issueId + "] "
                                + issue.name()
                                + " | url=" + issueUrl
                                + " | sev=" + sev
                                + " | conf=" + conf
                );

                // Send reward to RL
                try {
                    rlClient.sendReward(reward);
                } catch (Exception e) {
                    api.logging().logToError("[RL][ERROR] Failed to send reward: " + e.getMessage());
                }

                long rewardId = REWARD_ID_GEN.incrementAndGet();
                String rTs = Instant.now().toString();

                api.logging().logToOutput(
                        "[RL][REWARD][ts=" + rTs + "][rewardId=" + rewardId + "][issueId=" + issueId + "] "
                                + "value=" + reward
                );
            }
        };
    }

    // ---------------------------
    // Helpers
    // ---------------------------

    private static String safeName(Object enumLike) {
        if (enumLike == null) return "UNKNOWN";
        try {
            // Many Montoya enums have .name()
            Method m = enumLike.getClass().getMethod("name");
            Object v = m.invoke(enumLike);
            return v != null ? v.toString() : "UNKNOWN";
        } catch (Exception ignored) {
            return enumLike.toString();
        }
    }

    /**
     * Tries multiple ways to derive a URL without compile-time dependency on issue.url().
     * Uses reflection so it compiles even if the method doesn't exist.
     */
    private static String tryGetIssueUrl(AuditIssue issue) {
        if (issue == null) return "N/A";

        // 1) Try issue.url() if present (some versions)
        try {
            Method m = issue.getClass().getMethod("url");
            Object v = m.invoke(issue);
            if (v != null) return v.toString();
        } catch (Exception ignored) {}

        // 2) Try issue.httpService().host() as fallback
        try {
            Method hs = issue.getClass().getMethod("httpService");
            Object httpService = hs.invoke(issue);
            if (httpService != null) {
                Method host = httpService.getClass().getMethod("host");
                Object hv = host.invoke(httpService);
                if (hv != null) return "http(s)://" + hv.toString();
            }
        } catch (Exception ignored) {}

        // 3) Last fallback
        return "N/A";
    }
}
