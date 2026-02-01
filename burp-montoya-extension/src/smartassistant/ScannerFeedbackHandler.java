import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.audit.AuditIssueHandler;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicLong;

public class ScannerFeedbackHandler {

    // === ID generators (runtime, in-memory) ===
    private static final AtomicLong ISSUE_ID_GEN  = new AtomicLong(0);
    private static final AtomicLong REWARD_ID_GEN = new AtomicLong(0);

    public static AuditIssueHandler asAuditIssueHandler(
            MontoyaApi api,
            RLHttpClient rlClient
    ) {
        return new AuditIssueHandler() {

            @Override
            public void handleNewAuditIssue(AuditIssue issue) {

                long issueId  = ISSUE_ID_GEN.incrementAndGet();
                String ts     = Instant.now().toString();

                int reward = 0;

                // Reward based on severity
                switch (issue.severity().name()) {
                    case "HIGH" -> reward += 5;
                    case "MEDIUM" -> reward += 3;
                    case "LOW" -> reward += 1;
                    default -> reward += 0;
                }

                // Reward based on confidence
                switch (issue.confidence().name()) {
                    case "FIRM" -> reward += 2;
                    case "TENTATIVE" -> reward -= 1;
                    default -> reward += 0;
                }

                api.logging().logToOutput(
                        "[RL][SCAN][ts=" + ts + "][issueId=" + issueId + "] "
                                + issue.name()
                                + " | sev=" + issue.severity()
                                + " | conf=" + issue.confidence()
                );

                // Send reward to RL
                rlClient.sendReward(reward);

                long rewardId = REWARD_ID_GEN.incrementAndGet();
                String rTs    = Instant.now().toString();

                api.logging().logToOutput(
                        "[RL][REWARD][ts=" + rTs + "][rewardId=" + rewardId + "][issueId=" + issueId + "] "
                                + "value=" + reward
                );
            }
        };
    }
}
