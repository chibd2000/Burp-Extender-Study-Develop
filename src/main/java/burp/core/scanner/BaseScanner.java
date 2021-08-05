package burp.core.scanner;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.utils.BurpAnalyzedRequest;

import java.io.PrintWriter;

public abstract class BaseScanner {
    public IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    public BurpAnalyzedRequest burpAnalyzedRequest;
    public IHttpRequestResponse httpRequestResponse;
    public PrintWriter stdout;
    public String scannerName;
    public BaseScanner(String scannerName){
        this.scannerName = scannerName;
    }
    public String getScannerName() {
        return this.scannerName;
    }
}
