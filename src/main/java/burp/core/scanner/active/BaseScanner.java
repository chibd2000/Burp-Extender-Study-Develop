package burp.core.scanner.active;

import burp.IHttpRequestResponse;
import burp.IScanIssue;

public abstract class BaseScanner {
    public String scannerName;
    public BaseScanner(String scannerName){
        this.scannerName = scannerName;
    }
    public abstract IScanIssue exportIssue(IHttpRequestResponse httpRequestResponse);
}
