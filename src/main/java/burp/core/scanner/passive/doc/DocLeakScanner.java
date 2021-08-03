package burp.core.scanner.passive.doc;

import burp.IHttpRequestResponse;
import burp.IScanIssue;
import burp.core.scanner.active.IActiveScanner;
import burp.core.scanner.passive.BasePassiveScanner;
import burp.core.scanner.passive.IPassiveScanner;

import java.util.List;

public class DocLeakScanner extends BasePassiveScanner implements Runnable, IPassiveScanner {

    public DocLeakScanner(String scannerName) {
        super(scannerName);
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

    @Override
    public List<String> getPayload() {
        return null;
    }

    @Override
    public List<IHttpRequestResponse> sendPayload() {
        return null;
    }

    @Override
    public IScanIssue exportIssue(IHttpRequestResponse httpRequestResponse) {
        return null;
    }
}
