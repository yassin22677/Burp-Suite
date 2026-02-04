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

    // --- Exploration parameters ---
    private static final int ACTION_SPACE = 5; // 0..4
    private static final double EPSILON_START = 1.0;
    private static final double EPSILON_MIN = 0.1;
    private static final double EPSILON_DECAY = 0.995;

    private double epsilon = EPSILON_START;
    private final Random random = new Random();

    public RLHttpClient(String decideUrl, String rewardUrl) {
        this.decideUrl = decideUrl;
        this.rewardUrl = rewardUrl;
    }

    // =====================================================
    // 🔹 PUBLIC: used by ProxyToRLActionsHandler
    // =====================================================
    public String postJson(String endpoint, String jsonBody) {
        try {
            HttpURLConnection conn =
                    (HttpURLConnection) new URL(endpoint).openConnection();

            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(jsonBody.getBytes(StandardCharsets.UTF_8));
            }

            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8)
            )) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line);
                }
                return sb.toString();
            }

        } catch (Exception e) {
            return "";
        }
    }

    // =====================================================
    // RL DECISION (UNCHANGED LOGIC)
    // =====================================================
    public int decideAction(String method, String url, int urlLen, int status) {

        // 🔥 EXPLORATION
        if (random.nextDouble() < epsilon) {
            decayEpsilon();
            return random.nextInt(ACTION_SPACE);
        }

        // 🔥 EXPLOITATION (ask Python RL)
        try {
            String json =
                    "{"
                            + "\"method\":\"" + escape(method) + "\","
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

            int action = Integer.parseInt(
                    new String(conn.getInputStream().readAllBytes(), StandardCharsets.UTF_8)
                            .trim()
            );

            decayEpsilon();
            return action;

        } catch (Exception e) {
            // Fail-safe
            return 0;
        }
    }

    // =====================================================
    // REWARD SENDING (UNCHANGED)
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

            conn.getInputStream().close();

        } catch (Exception ignored) {
        }
    }

    // =====================================================
    // HELPERS
    // =====================================================
    private void decayEpsilon() {
        if (epsilon > EPSILON_MIN) {
            epsilon *= EPSILON_DECAY;
        }
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
