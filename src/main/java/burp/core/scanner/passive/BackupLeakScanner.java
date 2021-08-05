package burp.core.scanner.passive;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.core.scanner.BaseScanner;
import burp.core.scanner.active.IActiveScanner;
import burp.utils.BurpAnalyzedRequest;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class BackupLeakScanner extends BaseScanner implements IActiveScanner, Runnable{
    public BackupLeakScanner(IBurpExtenderCallbacks callbacks, IHttpRequestResponse httpRequestResponse) {
        super("BackupLeak");
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.burpAnalyzedRequest = new BurpAnalyzedRequest();
        this.httpRequestResponse = httpRequestResponse;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
    }

    @Override
    public List<String> getPayload() {
        List<String> payloadList = new ArrayList<>();
        payloadList.add("111");
        return payloadList;
    }

    @Override
    public List<IHttpRequestResponse> sendPayload() {
        List<String> payloadList = this.getPayload();
        List<IHttpRequestResponse> responseList = new ArrayList<>();
        IRequestInfo RequestInfo = this.helpers.analyzeRequest(this.httpRequestResponse);
        List<String> headers = RequestInfo.getHeaders();
        for (String payload : payloadList) {
            String s = headers.get(0);
            if (s.contains("HTTP/1.1") && s.contains("GET")) {
                String s1 = s.replaceFirst("\\s(.*)\\s", " " + payload + " ");
                headers.set(0, s1);
            }
            byte[] requestBytes = this.helpers.buildHttpMessage(headers, burpAnalyzedRequest.getRequestBody(this.httpRequestResponse));
            IHttpRequestResponse response = this.callbacks.makeHttpRequest(this.httpRequestResponse.getHttpService(), requestBytes);
            responseList.add(response);
        }
        return responseList;
    }

    @Override
    public void run() {
        // 判断URL的重复
        String requestUrl = this.burpAnalyzedRequest.getRequestDomain(this.httpRequestResponse)+
                this.burpAnalyzedRequest.getRequestURI(this.httpRequestResponse);
        String requestUrlRoot = requestUrl.endsWith("/") ? requestUrl : requestUrl.substring(0,requestUrl.lastIndexOf("/")+1);
        this.stdout.println("======a=========");
        this.stdout.println(requestUrlRoot);
        this.stdout.println("======a=========");
        boolean check = BurpExtender.urlRepeatMap.check(requestUrlRoot);
        if (check){
            return;
        }
        BurpExtender.urlRepeatMap.add(requestUrl);

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
            if (responseContent.contains("gz")) {
                BurpExtender.tags.add(
                        this.getScannerName(),
                        this.burpAnalyzedRequest.getRequestDomain(response),
                        this.burpAnalyzedRequest.getStatusCode(response) + "",
                        "[+] found backup leak",
                        this.httpRequestResponse
                );
            }
        }
    }

    class BackupPayload{
        public List<String> expList;
        public BackupPayload(String requestURI){
            List<String> payloadList = new ArrayList<>();
            if (requestURI.endsWith("/")) {// http://a.com/ -> / -> + env和 http://a.com/user/ -> / -> + env
                payloadList.add(requestURI + "www.rar");
                payloadList.add(requestURI + "www.zip");
                payloadList.add(requestURI + "backup.rar");
                payloadList.add(requestURI + "actuator/httptrace");
            }else{
                payloadList.add(requestURI + "/env");
                payloadList.add(requestURI + "/trace");
                payloadList.add(requestURI + "/actuator/env");
                payloadList.add(requestURI + "/actuator/httptrace");
            }
            this.expList = payloadList;
        }

        public List<String> getExp() {
            return expList;
        }
    }

    class BackupDomainPyload{

    }
}
