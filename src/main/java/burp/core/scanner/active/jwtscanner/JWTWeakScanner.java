package burp.core.scanner.active.jwtscanner;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.core.scanner.active.BaseActiveScanner;
import burp.utils.BurpAnalyzedRequest;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;

public class JWTWeakScanner extends BaseActiveScanner implements ActionListener {

    public JWTWeakScanner(IBurpExtenderCallbacks callbacks, IHttpRequestResponse httpRequestResponse){
        super("JwtWeakKeyScanner");
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.burpAnalyzedRequest = new BurpAnalyzedRequest();
        this.httpRequestResponse = httpRequestResponse;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
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
