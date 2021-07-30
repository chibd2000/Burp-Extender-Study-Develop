package burp.core.scanner.active;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.utils.BurpAnalyzedRequest;

import java.io.PrintWriter;

public abstract class BaseActiveScanner {
    public IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    public BurpAnalyzedRequest burpAnalyzedRequest;
    public IHttpRequestResponse httpRequestResponse;
    public PrintWriter stdout;
    public String scannerName;
    public BaseActiveScanner(String scannerName){
        this.scannerName = scannerName;
    }
    public abstract IScanIssue exportIssue(IHttpRequestResponse httpRequestResponse);
}