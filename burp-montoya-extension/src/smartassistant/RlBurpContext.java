import burp.api.montoya.MontoyaApi;

/**
 * Loads API token, optional users.id (loopback dev), and scan session id from env / preferences.
 */
public final class RlBurpContext {

    private static final String PREF_API_TOKEN = "rl_api_token";
    private static final String PREF_USER_ID = "burp_rl_user_id";
    private static final String PREF_SESSION_ID = "burp_scan_session_id";

    private RlBurpContext() {}

    public static void apply(MontoyaApi api, RLHttpClient client) {
        String token = firstNonBlank(System.getenv("BURP_RL_API_TOKEN"));
        if (token == null) {
            try {
                token = firstNonBlank(api.persistence().preferences().getString(PREF_API_TOKEN));
            } catch (Exception ignored) {
            }
        }
        client.setApiToken(token);

        Long userId = null;
        String uidEnv = System.getenv("BURP_RL_USER_ID");
        if (uidEnv != null && !uidEnv.isBlank()) {
            try {
                userId = Long.parseLong(uidEnv.trim());
            } catch (NumberFormatException ignored) {
            }
        }
        if (userId == null) {
            try {
                Integer ui = api.persistence().preferences().getInteger(PREF_USER_ID);
                if (ui != null) {
                    userId = ui.longValue();
                }
            } catch (Exception ignored) {
            }
        }
        if (userId == null) {
            try {
                String us = api.persistence().preferences().getString(PREF_USER_ID);
                if (us != null && !us.isBlank()) {
                    userId = Long.parseLong(us.trim());
                }
            } catch (Exception ignored) {
            }
        }
        client.setDashboardUserId(userId);

        Long sessionId = null;
        try {
            Integer sid = api.persistence().preferences().getInteger(PREF_SESSION_ID);
            if (sid != null) {
                sessionId = sid.longValue();
            }
        } catch (Exception ignored) {
        }
        client.setScanSessionId(sessionId);

        client.ensureScanSession(api);
    }

    private static String firstNonBlank(String s) {
        if (s == null) {
            return null;
        }
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }
}
