package burp.core.scanner.passive.git;

import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.core.scanner.passive.BasePassiveScanner;
import burp.core.scanner.passive.IPassiveScanner;

public class GitLeakScanner extends BasePassiveScanner implements IPassiveScanner {


    public GitLeakScanner(String scannerName) {
        super(scannerName);
    }

    @Override
    public String getScannerName() {
        return null;
    }

    @Override
    public IScanIssue exportIssue(IHttpRequestResponse httpRequestResponse) {
        return null;
    }

    @Override
    public void scan() {

    }
}
