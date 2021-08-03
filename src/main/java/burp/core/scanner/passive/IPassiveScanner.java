package burp.core.scanner.passive;

import burp.IHttpRequestResponse;
import burp.IScanIssue;

import java.util.List;

public interface IPassiveScanner {
    List<String> getPayload();
    List<IHttpRequestResponse> sendPayload();
    IScanIssue exportIssue(IHttpRequestResponse httpRequestResponse);
}
