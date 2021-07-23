package burp.core.scanner.passive;

import burp.IHttpRequestResponse;
import burp.IScanIssue;

public abstract class BaseScanner {
    public String scannerName;

    public BaseScanner(String scannerName){
        this.scannerName = scannerName;
    }
    public abstract String getScannerName();
    public abstract IScanIssue export(IHttpRequestResponse httpRequestResponse);
}
