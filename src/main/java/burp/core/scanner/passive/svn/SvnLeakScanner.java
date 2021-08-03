package burp.core.scanner.passive.svn;

import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.core.scanner.passive.BasePassiveScanner;
import burp.core.scanner.passive.IPassiveScanner;

import java.util.List;

public class SVNLeakScanner extends BasePassiveScanner implements IPassiveScanner {
    public SVNLeakScanner() {
        super("SvnLeakScanner");
    }

    @Override
    public List<String> getPayload() {
        return null;
    }

    @Override
    public List<IHttpRequestResponse> sendPayload() {
        return null;
    }

    @Override
    public IScanIssue exportIssue(IHttpRequestResponse httpRequestResponse) {
        return null;
    }
}
