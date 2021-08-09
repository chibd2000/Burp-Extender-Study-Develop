package burp.core.scanner.passive;

import burp.IHttpRequestResponse;

import java.util.List;

public interface IPassiveScanner {
    List<String> getPayload();
    List<IHttpRequestResponse> sendPayload();
    void run();
}
