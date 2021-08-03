package burp.core.scanner.passive.svn;

import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.core.scanner.passive.BasePassiveScanner;
import burp.core.scanner.passive.IPassiveScanner;

public class SVNLeakScanner extends BasePassiveScanner implements IPassiveScanner {
    public SVNLeakScanner() {
        super("SvnLeakScanner");
    }

    @Override
    public IScanIssue exportIssue(IHttpRequestResponse httpRequestResponse) {
        return null;
    }

    @Override
    public void scan() {

    }
}
