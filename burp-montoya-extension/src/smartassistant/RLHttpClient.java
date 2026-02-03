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

    /**
     * Decide action using ε-greedy strategy.
     */
    public int decideAction(String method, String url, int urlLen, int status) {

        // 🔥 EXPLORATION
        if (random.nextDouble() < epsilon) {
            decayEpsilon();
            return random.nextInt(ACTION_SPACE);
        }

        // 🔥 EXPLOITATION (ask Python RL)
        try {
            String json = """
                {
                  "method": "%s",
                  "url_length": %d,
                  "status": %d
                }
                """.formatted(method, urlLen, status);

            HttpURLConnection conn =
                    (HttpURLConnection) new URL(decideUrl).openConnection();

            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(json.getBytes(StandardCharsets.UTF_8));
            }

            int action = Integer.parseInt(
                    new String(conn.getInputStream().readAllBytes())
                            .trim()
            );

            decayEpsilon();
            return action;

        } catch (Exception e) {
            // Fail-safe
            return 0;
        }
    }

    /**
     * Send reward to Python RL agent.
     */
    public void sendReward(int reward) {
        try {
            String json = """
                { "reward": %d }
                """.formatted(reward);

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

    private void decayEpsilon() {
        if (epsilon > EPSILON_MIN) {
            epsilon *= EPSILON_DECAY;
        }
    }
}
