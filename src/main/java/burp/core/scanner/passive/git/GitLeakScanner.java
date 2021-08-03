package burp.core.scanner.passive.git;

import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.core.scanner.passive.BasePassiveScanner;
import burp.core.scanner.passive.IPassiveScanner;
import burp.utils.BurpAnalyzedRequest;

import java.util.List;

public class GitLeakScanner extends BasePassiveScanner implements IPassiveScanner {
    public IHttpRequestResponse httpRequestResponse;
    public BurpAnalyzedRequest burpAnalyzedRequest;
    public GitLeakScanner(IHttpRequestResponse httpRequestResponse) {
        super("GitLeakScanner");
        this.httpRequestResponse = httpRequestResponse;
        this.burpAnalyzedRequest = new BurpAnalyzedRequest();
    }

    @Override
    public IScanIssue exportIssue(IHttpRequestResponse httpRequestResponse) {
        return null;
    }


    @Override
    public List<String> getPayload() {
        return null;
    }

    @Override
    public List<IHttpRequestResponse> sendPayload() {
        return null;
    }
}
