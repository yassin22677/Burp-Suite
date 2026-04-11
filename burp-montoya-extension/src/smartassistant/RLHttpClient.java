import burp.api.montoya.MontoyaApi;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RLHttpClient {

    private final String apiBase;
    private final String decideUrl;
    private final String rewardUrl;
    private final String logUrl;

    private volatile String apiToken;
    /** Optional users.id for loopback dev when no api_token (preference burp_rl_user_id). */
    private volatile Long dashboardUserId;
    /** FK to sessions.id; chosen automatically via /api/scan/start when token is set. */
    private volatile Long scanSessionId;

    private static final Pattern SESSION_ID_JSON =
            Pattern.compile("\"session_id\"\\s*:\\s*(\\d+)");
    private static final Pattern USER_ID_JSON =
            Pattern.compile("\"user_id\"\\s*:\\s*(\\d+)");

    // --- Exploration parameters ---
    private static final int ACTION_SPACE = 5;
    private static final double EPSILON_START = 1.0;
    private static final double EPSILON_MIN = 0.1;
    private static final double EPSILON_DECAY = 0.995;

    private double epsilon = EPSILON_START;
    private final Random random = new Random();

    public RLHttpClient(String apiBase, String decideUrl, String rewardUrl, String logUrl) {
        String b = apiBase == null ? "" : apiBase.trim();
        if (b.endsWith("/")) {
            b = b.substring(0, b.length() - 1);
        }
        this.apiBase = b;
        this.decideUrl = decideUrl;
        this.rewardUrl = rewardUrl;
        this.logUrl = logUrl;
    }

    public void setApiToken(String apiToken) {
        this.apiToken = apiToken;
    }

    public String getApiToken() {
        return apiToken;
    }

    public void setScanSessionId(Long scanSessionId) {
        this.scanSessionId = scanSessionId;
    }

    public Long getScanSessionId() {
        return scanSessionId;
    }

    public void setDashboardUserId(Long dashboardUserId) {
        this.dashboardUserId = dashboardUserId;
    }

    /**
     * If an API token is set but no session yet, create one on the server and persist id in
     * Montoya preferences (no manual UUID copy). Without token, uses dashboardUserId on loopback only.
     */
    public void ensureScanSession(MontoyaApi api) {
        boolean hasToken = apiToken != null && !apiToken.isBlank();
        boolean hasUser = dashboardUserId != null;
        if (!hasToken && !hasUser) {
            System.err.println(
                    "[RLHttpClient] Configure rl_api_token (or BURP_RL_API_TOKEN) or burp_rl_user_id "
                            + "(or BURP_RL_USER_ID) so /api/scan/start and /api/rl-events can map your user.");
            return;
        }
        if (scanSessionId != null) {
            return;
        }
        try {
            long id = postScanStart(api, "\"target_url\":\"https://burp/active\"");
            scanSessionId = id;
            try {
                api.persistence().preferences().setInteger(
                        "burp_scan_session_id", Math.toIntExact(id));
            } catch (Exception ignored) {
            }
        } catch (Exception e) {
            System.err.println("[RLHttpClient] ensureScanSession: " + e.getMessage());
        }
    }

    private long postScanStart(MontoyaApi api, String targetUrlJsonField) throws IOException {
        String tok = apiToken == null ? "" : apiToken.trim();
        String jsonBody = "{" + targetUrlJsonField;
        if (!tok.isEmpty()) {
            jsonBody += ",\"api_token\":\"" + escapeJson(tok) + "\"";
        } else if (dashboardUserId != null) {
            jsonBody += ",\"user_id\":" + dashboardUserId;
        }
        jsonBody += "}";
        HttpURLConnection conn =
                (HttpURLConnection) new URL(apiBase + "/api/scan/start").openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
        if (!tok.isEmpty()) {
            conn.setRequestProperty("Authorization", "Bearer " + tok);
        }
        conn.setDoOutput(true);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(jsonBody.getBytes(StandardCharsets.UTF_8));
        }
        int code = conn.getResponseCode();
        InputStream stream = code >= 400 ? conn.getErrorStream() : conn.getInputStream();
        String body = new String(stream.readAllBytes(), StandardCharsets.UTF_8).trim();
        Matcher m = SESSION_ID_JSON.matcher(body);
        if (!m.find()) {
            throw new IOException("HTTP " + code + " — " + body);
        }
        long sessionId = Long.parseLong(m.group(1));
        Matcher um = USER_ID_JSON.matcher(body);
        if (um.find()) {
            try {
                long uid = Long.parseLong(um.group(1));
                dashboardUserId = uid;
                if (api != null) {
                    try {
                        api.persistence().preferences().setInteger(
                                "burp_rl_user_id", Math.toIntExact(uid));
                    } catch (Exception ignored) {
                    }
                }
            } catch (NumberFormatException ignored) {
            }
        }
        return sessionId;
    }

    private void applyBearer(HttpURLConnection conn) {
        String tok = apiToken;
        if (tok != null && !tok.isBlank()) {
            conn.setRequestProperty("Authorization", "Bearer " + tok.trim());
        }
    }

    // =====================================================
    // RAW LOG MIRRORING (EXACT BURP LINE -> DASHBOARD)
    // =====================================================
    public void sendLog(String eventType, String rawLine) {
        try {
            StringBuilder json = new StringBuilder(256);
            json.append("{");
            json.append("\"event_type\":\"").append(escapeJson(eventType)).append("\",");
            json.append("\"raw_line\":\"").append(escapeJson(rawLine)).append("\"");
            Long sid = scanSessionId;
            if (sid != null) {
                json.append(",\"session_id\":").append(sid);
            }
            String tok = apiToken;
            if (tok != null && !tok.isBlank()) {
                json.append(",\"api_token\":\"").append(escapeJson(tok.trim())).append("\"");
            }
            Long du = dashboardUserId;
            if (du != null) {
                json.append(",\"user_id\":").append(du);
            }
            json.append("}");

            HttpURLConnection conn =
                    (HttpURLConnection) new URL(logUrl).openConnection();

            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json; charset=utf-8");
            applyBearer(conn);
            conn.setDoOutput(true);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(json.toString().getBytes(StandardCharsets.UTF_8));
            }

            int code = conn.getResponseCode();
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(
                            code >= 400 ? conn.getErrorStream() : conn.getInputStream(),
                            StandardCharsets.UTF_8
                    ))) {
                while (br.readLine() != null) { /* ignore body */ }
            }

            if (code < 200 || code >= 300) {
                System.err.println(
                        "[RLHttpClient] sendLog failed: HTTP " + code + " -> " + logUrl
                                + " (check API token and /api/rl-events auth)");
            }

        } catch (Exception e) {
            System.err.println(
                    "[RLHttpClient] sendLog error: " + e.getMessage() + " -> " + logUrl);
        }
    }

    // =====================================================
    // RL DECISION
    // =====================================================
    public int decideAction(String method, String url, int urlLen, int status) {

        if (random.nextDouble() < epsilon) {
            decayEpsilon();
            return random.nextInt(ACTION_SPACE);
        }

        try {
            String json =
                    "{"
                            + "\"method\":\"" + escapeJson(method) + "\","
                            + "\"url\":\"" + escapeJson(url) + "\","
                            + "\"url_length\":" + urlLen + ","
                            + "\"status\":" + status
                            + "}";

            HttpURLConnection conn =
                    (HttpURLConnection) new URL(decideUrl).openConnection();

            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            applyBearer(conn);
            conn.setDoOutput(true);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(json.getBytes(StandardCharsets.UTF_8));
            }

            String body = new String(
                    (conn.getResponseCode() >= 400 ? conn.getErrorStream() : conn.getInputStream()).readAllBytes(),
                    StandardCharsets.UTF_8
            ).trim();

            int action = Integer.parseInt(body);

            decayEpsilon();
            return action;

        } catch (Exception e) {
            return 0;
        }
    }

    // =====================================================
    // REWARD
    // =====================================================
    public void sendReward(int reward) {
        try {
            String json = "{ \"reward\": " + reward + " }";

            HttpURLConnection conn =
                    (HttpURLConnection) new URL(rewardUrl).openConnection();

            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            applyBearer(conn);
            conn.setDoOutput(true);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(json.getBytes(StandardCharsets.UTF_8));
            }

            if (conn.getResponseCode() >= 400) {
                conn.getErrorStream().close();
            } else {
                conn.getInputStream().close();
            }

        } catch (Exception ignored) {
        }
    }

    private void decayEpsilon() {
        if (epsilon > EPSILON_MIN) {
            epsilon *= EPSILON_DECAY;
        }
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\r", "\\r")
                .replace("\n", "\\n");
    }
}
