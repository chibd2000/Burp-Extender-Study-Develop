package burp.core.scanner.active.jwtscanner;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.core.scanner.active.BaseScanner;
import burp.utils.BurpAnalyzedRequest;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class JWTWeakScanner extends BaseScanner implements ActionListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private BurpAnalyzedRequest analyzedRequest;

    public JWTWeakScanner(IBurpExtenderCallbacks callbacks, BurpAnalyzedRequest analyzedRequest){
        super("JwtWeakScanner");
        this.callbacks = callbacks;
        this.analyzedRequest = analyzedRequest;
        this.helpers = callbacks.getHelpers();
    }

    /**
     * Invoked when an action occurs.
     *
     * @param e
     */
    @Override
    public void actionPerformed(ActionEvent e) {
        System.out.println("jwtScanner click me...");

    }

    @Override
    public IScanIssue exportIssue(IHttpRequestResponse httpRequestResponse) {
        return null;
    }
}
