package burp.core.scanner.active.shiroscanner;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.core.scanner.active.BaseActiveScanner;
import burp.utils.BurpAnalyzedRequest;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;

public class ShiroBypassScanner extends BaseActiveScanner implements ActionListener, Runnable {

    public ShiroBypassScanner(IBurpExtenderCallbacks callbacks, IHttpRequestResponse httpRequestResponse){
        super("ShiroBypassScanner");
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
        System.out.println("shiroScanner click me...");

    }

    @Override
    public IScanIssue exportIssue(IHttpRequestResponse httpRequestResponse) {
        return null;
    }

    /**
     * When an object implementing interface <code>Runnable</code> is used
     * to create a thread, starting the thread causes the object's
     * <code>run</code> method to be called in that separately executing
     * thread.
     * <p>
     * The general contract of the method <code>run</code> is that it may
     * take any action whatsoever.
     *
     * @see Thread#run()
     */
    @Override
    public void run() {

    }
}
