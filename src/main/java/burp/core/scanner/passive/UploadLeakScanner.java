package burp.core.scanner.passive;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.core.scanner.BaseScanner;
import burp.utils.BurpAnalyzedRequest;

import java.io.PrintWriter;
import java.util.List;

public class UploadLeakScanner extends BaseScanner implements IPassiveScanner, Runnable{
    public UploadLeakScanner(IBurpExtenderCallbacks callbacks, IHttpRequestResponse httpRequestResponse) {
        super("UploadLeak");
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.burpAnalyzedRequest = new BurpAnalyzedRequest();
        this.httpRequestResponse = httpRequestResponse;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
    }

    @Override
    public List<String> getPayload() {
        return null;
    }

    @Override
    public List<IHttpRequestResponse> sendPayload() {
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
