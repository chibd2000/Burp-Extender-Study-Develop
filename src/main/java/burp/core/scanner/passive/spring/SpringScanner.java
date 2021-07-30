package burp.core.scanner.passive.spring;

import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.core.scanner.passive.BasePassiveScanner;
import burp.core.scanner.passive.IPassiveScanner;

public class SpringScanner extends BasePassiveScanner implements IPassiveScanner, Runnable {

    public SpringScanner(String scannerName) {
        super(scannerName);
    }

    @Override
    public String getScannerName() {
        return null;
    }

    @Override
    public IScanIssue exportIssue(IHttpRequestResponse httpRequestResponse) {
        return null;
    }

    @Override
    public void scan() {

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
