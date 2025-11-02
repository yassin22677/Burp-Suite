package smartassistant;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.net.URL;
import java.net.MalformedURLException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Montoya-compatible extension for your montoya-api.jar (handler-based API).
 * - Builds the JSON your Flask model expects and posts asynchronously.
 * - Logs results into Extender -> Output.
 */
public class SmartAssistantExtension implements BurpExtension {

    private MontoyaApi montoyaApi;

    // model API config
    private static final String MODEL_API_URL = "http://127.0.0.1:5001/recommend";
    private static final String API_KEY = "my_secret_key_123";

    private final ExecutorService apiThreadPool = Executors.newFixedThreadPool(6);

    @Override
    public void initialize(MontoyaApi api) {
        this.montoyaApi = api;
        montoyaApi.extension().setName("Smart Assistant Extension");
        montoyaApi.logging().logToOutput("✅ Smart Assistant Extension loaded (handler API).");

        montoyaApi.http().registerHttpHandler(new HttpHandler() {

            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
                // do not modify outgoing requests
               return RequestToBeSentAction.continueWith(requestToBeSent);



            }

            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
                try {
                    // initiatingRequest() in this API returns an HttpRequest (message/requests/HttpRequest)
                    HttpRequest initiatingReq = responseReceived.initiatingRequest();
                   HttpResponse response = responseReceived;




                    // url() and method() return Strings in this API
                    String urlStr = initiatingReq.url();
                    String methodStr = initiatingReq.method();
                    int statusCode = response.statusCode();

                    // derive host and path safely (url may be relative => guard with try/catch)
                    String host = urlStr;
                    String path = urlStr;
                    try {
                        URL parsed = new URL(urlStr);
                        host = parsed.getHost();
                        path = parsed.getPath();
                    } catch (MalformedURLException e) {
                        // urlStr might be relative; fall back to full string
                    }

                    // matched rules—replace with your detection logic if available
                    int matchedRulesCount = 0;

                    // placeholder categorical fields (match your model's training names)
                    String attackType = "generic";
                    String attackSubtype = "generic";
                    String severity = "Low";
                    String confidence = "Low";

                    // basic static asset filter
                    if (path != null) {
                        String lower = path.toLowerCase();
                        if (lower.endsWith(".png") || lower.endsWith(".jpg") || lower.endsWith(".jpeg")
                                || lower.endsWith(".gif") || lower.endsWith(".css") || lower.endsWith(".js")
                                || lower.endsWith(".woff") || lower.endsWith(".woff2") || lower.endsWith(".ico")) {
                            return ResponseReceivedAction.continueWith(response);
                        }
                    }

                    String sessionId = System.currentTimeMillis() + "_" + host;

                    // build JSON payload expected by your Flask API
                    String payload = String.format(
                        "{\"session_id\":\"%s\",\"features\":{" +
                            "\"status_code\":%d," +
                            "\"matched_rules_count\":%d," +
                            "\"http_method\":\"%s\"," +
                            "\"attack_type\":\"%s\"," +
                            "\"attack_subtype\":\"%s\"," +
                            "\"severity\":\"%s\"," +
                            "\"confidence\":\"%s\"" +
                        "}}",
                        escapeJson(sessionId),
                        statusCode,
                        matchedRulesCount,
                        escapeJson(methodStr),
                        escapeJson(attackType),
                        escapeJson(attackSubtype),
                        escapeJson(severity),
                        escapeJson(confidence)
                    );

                    // send asynchronously
                    apiThreadPool.submit(() -> postPayloadToModelApi(payload));

                } catch (Throwable t) {
                    // Log unexpected errors
                    montoyaApi.logging().logToError("ML forwarder exception: " + t.getMessage());
                }

                return ResponseReceivedAction.continueWith(responseReceived);


            }
        });

        montoyaApi.logging().logToOutput("✅ HTTP handler registered (forwarding responses to model).");
    }

    // ---------------- Helpers ----------------

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String truncate(String s, int len) {
        if (s == null) return "";
        if (s.length() <= len) return s;
        return s.substring(0, len) + "...";
    }

    private void postPayloadToModelApi(String jsonPayload) {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(MODEL_API_URL);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
            conn.setRequestProperty("x-api-key", API_KEY);

            byte[] out = jsonPayload.getBytes(StandardCharsets.UTF_8);
            conn.setFixedLengthStreamingMode(out.length);
            conn.connect();

            try (OutputStream os = conn.getOutputStream()) {
                os.write(out);
            }

            int status = conn.getResponseCode();
            String responseBody = "";
            try (InputStream is = (status >= 200 && status < 400) ? conn.getInputStream() : conn.getErrorStream()) {
                if (is != null) responseBody = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            }

            montoyaApi.logging().logToOutput("[model-api] status=" + status +
                    " payload=" + truncate(jsonPayload, 200) +
                    " body=" + truncate(responseBody, 400));

        } catch (Exception e) {
            montoyaApi.logging().logToError("[model-api] POST failed: " + e.getMessage());
        } finally {
            if (conn != null) conn.disconnect();
        }
    }
}
