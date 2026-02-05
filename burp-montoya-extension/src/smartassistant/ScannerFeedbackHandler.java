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

                String sev = safeName(issue.severity());
                switch (sev) {
                    case "HIGH" -> reward += 5;
                    case "MEDIUM" -> reward += 3;
                    case "LOW" -> reward += 1;
                    default -> reward += 0;
                }

                String conf = safeName(issue.confidence());
                switch (conf) {
                    case "FIRM" -> reward += 2;
                    case "TENTATIVE" -> reward -= 1;
                    default -> reward += 0;
                }

                String issueUrl = tryGetIssueUrl(issue);

                String lineSCAN =
                        "[RL][SCAN][ts=" + ts + "][issueId=" + issueId + "] "
                                + issue.name()
                                + " | url=" + issueUrl
                                + " | sev=" + sev
                                + " | conf=" + conf;

                api.logging().logToOutput(lineSCAN);
                rlClient.sendLog("SCAN", lineSCAN);

                try {
                    rlClient.sendReward(reward);
                } catch (Exception e) {
                    String err = "[RL][ERROR] Failed to send reward: " + e.getMessage();
                    api.logging().logToError(err);
                    rlClient.sendLog("ERROR", err);
                }

                long rewardId = REWARD_ID_GEN.incrementAndGet();
                String rTs = Instant.now().toString();

                String lineREWARD =
                        "[RL][REWARD][ts=" + rTs + "][rewardId=" + rewardId + "][issueId=" + issueId + "] "
                                + "value=" + reward;

                api.logging().logToOutput(lineREWARD);
                rlClient.sendLog("REWARD", lineREWARD);
            }
        };
    }

    private static String safeName(Object enumLike) {
        if (enumLike == null) return "UNKNOWN";
        try {
            Method m = enumLike.getClass().getMethod("name");
            Object v = m.invoke(enumLike);
            return v != null ? v.toString() : "UNKNOWN";
        } catch (Exception ignored) {
            return enumLike.toString();
        }
    }

    private static String tryGetIssueUrl(AuditIssue issue) {
        if (issue == null) return "N/A";

        try {
            Method m = issue.getClass().getMethod("url");
            Object v = m.invoke(issue);
            if (v != null) return v.toString();
        } catch (Exception ignored) {}

        try {
            Method hs = issue.getClass().getMethod("httpService");
            Object httpService = hs.invoke(issue);
            if (httpService != null) {
                Method host = httpService.getClass().getMethod("host");
                Object hv = host.invoke(httpService);
                if (hv != null) return "http(s)://" + hv.toString();
            }
        } catch (Exception ignored) {}

        return "N/A";
    }
}
