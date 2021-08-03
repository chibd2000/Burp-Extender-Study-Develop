package burp.core.scanner.passive.git;

import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.core.scanner.passive.BasePassiveScanner;
import burp.core.scanner.passive.IPassiveScanner;
import burp.utils.BurpAnalyzedRequest;

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
    public void scan() {
        String requestURI = this.burpAnalyzedRequest.getRequestURI(this.httpRequestResponse);

    }

    public void getPayload(){

    }
}
