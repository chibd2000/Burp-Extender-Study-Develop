package burp.core.scanner.passive;

import burp.IHttpRequestResponse;
import burp.IScanIssue;

public interface IPassiveScanner {
    IScanIssue exportIssue(IHttpRequestResponse httpRequestResponse);
    void scan();
}
