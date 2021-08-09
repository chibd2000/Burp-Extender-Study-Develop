package burp.core.scanner.passive;

import burp.*;
import burp.core.scanner.BaseScanner;
import burp.core.scanner.active.IActiveScanner;
import burp.utils.BurpAnalyzedRequest;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class BackupLeakScanner extends BaseScanner implements IPassiveScanner{
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
        BackupPayload backupPayload = new BackupLeakScanner.BackupPayload(this.httpRequestResponse);
        return backupPayload.getExp();
    }

    @Override
    public List<IHttpRequestResponse> sendPayload() {
        List<String> payloadList = this.getPayload();
        List<IHttpRequestResponse> responseList = new ArrayList<>();
        IRequestInfo RequestInfo = this.helpers.analyzeRequest(this.httpRequestResponse);
        List<String> headers = RequestInfo.getHeaders();
        for (String payload : payloadList) {
            String s = headers.get(0);
            if (s.contains("HTTP/1.1")) {
                String s1 = s.replaceFirst("\\s(.*)\\s", " " + payload + " ");
                headers.set(0, s1);
            }
            byte[] requestBytes = this.helpers.buildHttpMessage(headers, burpAnalyzedRequest.getRequestBody(this.httpRequestResponse));
            IHttpRequestResponse response = this.callbacks.makeHttpRequest(this.httpRequestResponse.getHttpService(), requestBytes);
            responseList.add(response);
        }
        return responseList;
    }

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
            List<String> headers = this.burpAnalyzedRequest.getResponseHeaders(response);
            for (String header : headers) {
                if (header.contains("application/x-rar-compressed")
                        || header.contains("application/zip")
                        || header.contains("application/x-tar")
                        || header.contains("application/x-gzip")
                ) {
                    BurpExtender.tags.add(
                            this.getScannerName(),
                            this.burpAnalyzedRequest.getUrl(response).toString(),
                            this.burpAnalyzedRequest.getStatusCode(response) + "",
                            "[+] found backup leak",
                            response);
                    break;
                }
            }
        }
    }

    public class BackupPayload{
        public List<String> expList;
        public BackupPayload(IHttpRequestResponse httpRequestResponse){
            BurpAnalyzedRequest burpAnalyzedRequest = new BurpAnalyzedRequest();
            String requestURI = burpAnalyzedRequest.getRequestURI(httpRequestResponse);
            String host = burpAnalyzedRequest.getUrl(httpRequestResponse).getHost();
            List<String> generatePyload = new BackupRuleBaseDomainGenerater().getRule1Payload(host);
            List<String> payloadList = new ArrayList<>();
            if (requestURI.endsWith("/")) {
                payloadList.add(requestURI + "www.rar");
                payloadList.add(requestURI + "www.zip");
                payloadList.addAll(generatePyload);
            }else{
                payloadList.add(requestURI + "/www.rar");
                payloadList.add(requestURI + "/www.zip");
                for (String s : generatePyload) {
                    payloadList.add("/" + s);
                }
            }
            this.expList = payloadList;
        }

        public List<String> getExp() {
            return expList;
        }

        public class BackupRuleBaseDomainGenerater{
            public List<String> getRule1Payload(String host){
                List<String> payloadList = new ArrayList<>();
                int i = host.lastIndexOf(".");
                String host1 = host.substring(0,i);
                int j = host1.lastIndexOf(".");
                String host2 = host1.substring(j+1);
                payloadList.add("/" + host2 + ".rar");
                payloadList.add("/" + host2 + ".zip");
                payloadList.add("/" + host2 + ".gz");
                payloadList.add("/" + host2 + ".tar");
                return payloadList;
            }
        }
    }
}
