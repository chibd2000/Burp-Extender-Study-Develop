package burp.core.scanner.active.jwtscanner;

import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.core.scanner.active.BaseActiveScanner;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class JWTEncodeWeakScanner extends BaseActiveScanner implements ActionListener, Runnable {
    public JWTEncodeWeakScanner(String scannerName) {
        super(scannerName);
    }

    @Override
    public IScanIssue exportIssue(IHttpRequestResponse httpRequestResponse) {
        return null;
    }

    /**
     * Invoked when an action occurs.
     *
     * @param e
     */
    @Override
    public void actionPerformed(ActionEvent e) {

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
