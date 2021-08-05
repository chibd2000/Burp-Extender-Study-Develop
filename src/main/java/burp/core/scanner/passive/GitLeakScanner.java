package burp.core.scanner.passive;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.core.scanner.BaseScanner;
import burp.core.scanner.active.IActiveScanner;
import burp.utils.BurpAnalyzedRequest;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

/*
* git相关的源码泄露
* */
public class GitLeakScanner extends BaseScanner implements IActiveScanner, Runnable{
    public GitLeakScanner(IBurpExtenderCallbacks callbacks, IHttpRequestResponse httpRequestResponse) {
        super("GitLeak");
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.burpAnalyzedRequest = new BurpAnalyzedRequest();
        this.httpRequestResponse = httpRequestResponse;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
    }

    @Override
    public List<String> getPayload() {
        List<String> payloadList = new ArrayList<>();
        payloadList.add("/.git");
        return payloadList;
    }

    @Override
    public List<IHttpRequestResponse> sendPayload() {
        return null;
    }

    @Override
    public void run() {
        List<IHttpRequestResponse> responseList = null;

        try {
            responseList = this.sendPayload(); // 发送payload
        }catch (Exception e){
            e.printStackTrace();
        }

        if (responseList == null){
            return;
        }

        for (IHttpRequestResponse response : responseList) {
            String responseContent = this.burpAnalyzedRequest.getResponseContent(response);
            if (responseContent.contains("[core]")) {
                BurpExtender.tags.add(
                        this.getScannerName(),
                        this.burpAnalyzedRequest.getRequestDomain(response),
                        this.burpAnalyzedRequest.getStatusCode(response) + "",
                        "[+] found git leak",
                        this.httpRequestResponse
                );
            }
        }
    }
}
