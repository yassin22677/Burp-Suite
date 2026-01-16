import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.audit.AuditIssueHandler;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

public class ScannerFeedbackHandler {

    public static AuditIssueHandler asAuditIssueHandler(
            MontoyaApi api,
            RLHttpClient rlClient
    ) {
        return new AuditIssueHandler() {

            @Override
            public void handleNewAuditIssue(AuditIssue issue) {

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

                rlClient.sendReward(reward);

                api.logging().logToOutput(
                        "[RL][SCAN] "
                                + issue.name()
                                + " | sev=" + issue.severity()
                                + " | conf=" + issue.confidence()
                                + " | reward=" + reward
                );
            }
        };
    }
}
