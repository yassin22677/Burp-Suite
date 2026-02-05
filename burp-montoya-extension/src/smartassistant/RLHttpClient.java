import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Random;

public class RLHttpClient {

    private final String decideUrl;
    private final String rewardUrl;
    private final String logUrl;

    // --- Exploration parameters ---
    private static final int ACTION_SPACE = 5; // 0..4
    private static final double EPSILON_START = 1.0;
    private static final double EPSILON_MIN = 0.1;
    private static final double EPSILON_DECAY = 0.995;

    private double epsilon = EPSILON_START;
    private final Random random = new Random();

    public RLHttpClient(String decideUrl, String rewardUrl, String logUrl) {
        this.decideUrl = decideUrl;
        this.rewardUrl = rewardUrl;
        this.logUrl = logUrl;
    }

    // =====================================================
    // RAW LOG MIRRORING (EXACT BURP LINE -> DASHBOARD)
    // =====================================================
    public void sendLog(String eventType, String rawLine) {
        try {
            String json =
                    "{"
                            + "\"event_type\":\"" + escapeJson(eventType) + "\","
                            + "\"raw_line\":\"" + escapeJson(rawLine) + "\""
                            + "}";

            HttpURLConnection conn =
                    (HttpURLConnection) new URL(logUrl).openConnection();

            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(json.getBytes(StandardCharsets.UTF_8));
            }

            // Consume response (avoid socket leaks)
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(
                            conn.getResponseCode() >= 400 ? conn.getErrorStream() : conn.getInputStream(),
                            StandardCharsets.UTF_8
                    ))) {
                while (br.readLine() != null) { /* ignore body */ }
            }

        } catch (Exception ignored) {
            // Never break Burp flow because dashboard is down
        }
    }

    // =====================================================
    // RL DECISION (Java sends: method, url_length, status)
    // Flask MUST return a plain integer body (e.g. "0")
    // =====================================================
    public int decideAction(String method, String url, int urlLen, int status) {

        // Exploration
        if (random.nextDouble() < epsilon) {
            decayEpsilon();
            return random.nextInt(ACTION_SPACE);
        }

        // Exploitation: ask Python RL
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
            conn.setDoOutput(true);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(json.getBytes(StandardCharsets.UTF_8));
            }

            String body = new String(
                    (conn.getResponseCode() >= 400 ? conn.getErrorStream() : conn.getInputStream()).readAllBytes(),
                    StandardCharsets.UTF_8
            ).trim();

            // Body must be just: 0..4
            int action = Integer.parseInt(body);

            decayEpsilon();
            return action;

        } catch (Exception e) {
            // Fail-safe
            return 0;
        }
    }

    // =====================================================
    // REWARD (Java sends: {"reward": <int>})
    // =====================================================
    public void sendReward(int reward) {
        try {
            String json = "{ \"reward\": " + reward + " }";

            HttpURLConnection conn =
                    (HttpURLConnection) new URL(rewardUrl).openConnection();

            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(json.getBytes(StandardCharsets.UTF_8));
            }

            // Consume response
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

    // Escapes for JSON string values
    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\r", "\\r")
                .replace("\n", "\\n");
    }
}
