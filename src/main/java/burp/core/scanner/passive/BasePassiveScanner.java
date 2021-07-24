package burp.core.scanner.passive;

import burp.IHttpRequestResponse;
import burp.IScanIssue;

public abstract class BasePassiveScanner {
    public String scannerName;
    public BasePassiveScanner(String scannerName){
        this.scannerName = scannerName;
    }
    public abstract String getScannerName();
}
