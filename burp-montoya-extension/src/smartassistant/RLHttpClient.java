import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class RLHttpClient {

    private final String decideUrl;
    private final String rewardUrl;

    public RLHttpClient(String decideUrl, String rewardUrl) {
        this.decideUrl = decideUrl;
        this.rewardUrl = rewardUrl;
    }

    public int decideAction(String method, String url, int urlLength, int statusCode) {
        String json = "{"
                + "\"method\":\"" + escape(method) + "\","
                + "\"url\":\"" + escape(url) + "\","
                + "\"url_length\":" + urlLength + ","
                + "\"status_code\":" + statusCode
                + "}";

        String resp = postJson(decideUrl, json);

        // Expecting something like: {"action_id":3}
        int actionId = extractInt(resp, "action_id", 0);
        return actionId;
    }

    public void sendReward(int reward) {
        String json = "{\"reward\":" + reward + "}";
        postJson(rewardUrl, json);
    }

    private String postJson(String endpoint, String jsonBody) {
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(endpoint).openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(jsonBody.getBytes("UTF-8"));
            }

            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(conn.getInputStream(), "UTF-8")
            )) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) sb.append(line);
                return sb.toString();
            }
        } catch (Exception e) {
            return "{}";
        }
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static int extractInt(String json, String key, int defaultVal) {
        try {
            String pattern = "\"" + key + "\":";
            int idx = json.indexOf(pattern);
            if (idx < 0) return defaultVal;
            int start = idx + pattern.length();
            int end = start;
            while (end < json.length() && (Character.isDigit(json.charAt(end)) || json.charAt(end) == '-')) {
                end++;
            }
            return Integer.parseInt(json.substring(start, end));
        } catch (Exception e) {
            return defaultVal;
        }
    }
}
