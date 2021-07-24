package burp.core.scanner.active;

import burp.IHttpRequestResponse;
import burp.IScanIssue;

public abstract class BaseActiveScanner {
    public String scannerName;
    public abstract IScanIssue exportIssue(IHttpRequestResponse httpRequestResponse);
    public BaseActiveScanner(String scannerName){
        this.scannerName = scannerName;
    }
}
