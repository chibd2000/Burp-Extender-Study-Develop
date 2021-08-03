package burp.core.scanner.passive.spring;

import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.core.scanner.passive.BasePassiveScanner;
import burp.core.scanner.passive.IPassiveScanner;

public class SpringLeakScanner extends BasePassiveScanner implements IPassiveScanner {

    public SpringLeakScanner() {
        super("SpringLeakScanner");
    }

    @Override
    public IScanIssue exportIssue(IHttpRequestResponse httpRequestResponse) {
        return null;
    }

    @Override
    public void scan() {

    }
}
