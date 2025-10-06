import burp.api.montoya.MontoyaApi;
import burp.api.montoya.BurpExtension;

public class SmartAssistantExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.logging().logToOutput("✅ Smart Assistant Extension initialized!");
        api.logging().logToOutput("🚀 Montoya API connected successfully!");
    }
}
