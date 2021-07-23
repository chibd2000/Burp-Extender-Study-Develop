package burp.core.scanner.active.shiroscanner;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.core.scanner.active.BaseScanner;
import burp.utils.BurpAnalyzedRequest;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class SHIROScanner extends BaseScanner implements ActionListener {

    public IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    public BurpAnalyzedRequest analyzedRequest;
    public IHttpRequestResponse httpRequestResponse;

    public SHIROScanner(IBurpExtenderCallbacks callbacks, IHttpRequestResponse httpRequestResponse){
        super("CustomCheckNoneJwt");
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.analyzedRequest = new BurpAnalyzedRequest();
        this.httpRequestResponse = httpRequestResponse;

    }

    /**
     * Invoked when an action occurs.
     *
     * @param e
     */
    @Override
    public void actionPerformed(ActionEvent e) {
        System.out.println("shiroScanner click me...");

    }

    @Override
    public IScanIssue exportIssue(IHttpRequestResponse httpRequestResponse) {
        return null;
    }
}
