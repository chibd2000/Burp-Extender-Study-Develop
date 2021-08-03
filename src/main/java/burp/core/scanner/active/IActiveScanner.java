package burp.core.scanner.active;

import burp.IHttpRequestResponse;

import java.util.List;

public interface IActiveScanner {
    List<String> getPayload();
    List<IHttpRequestResponse> sendPayload();
}
