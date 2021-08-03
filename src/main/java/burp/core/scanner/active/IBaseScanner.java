package burp.core.scanner.active;

import burp.IHttpRequestResponse;

import java.util.List;

public interface IBaseScanner {
    public Object getPayload();
    public List<IHttpRequestResponse> sendPayload();
}
