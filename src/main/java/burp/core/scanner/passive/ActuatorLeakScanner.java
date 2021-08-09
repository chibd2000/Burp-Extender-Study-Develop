package burp.core.scanner.passive;

import burp.*;
import burp.core.scanner.BaseScanner;
import burp.utils.BurpAnalyzedRequest;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class ActuatorLeakScanner extends BaseScanner implements IPassiveScanner{
    public ActuatorLeakScanner(IBurpExtenderCallbacks callbacks, IHttpRequestResponse httpRequestResponse) {
        super("ActuatorLeak");
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.burpAnalyzedRequest = new BurpAnalyzedRequest();
        this.httpRequestResponse = httpRequestResponse;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
    }

    @Override
    public List<String> getPayload() {
        String requestURI = this.burpAnalyzedRequest.getRequestURI(this.httpRequestResponse);
        return new ActuatorPayload(requestURI).getExp();
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
            String responseBody = new String(this.burpAnalyzedRequest.getResponseBody(response));
            if (responseBody.contains("Environment") //env
                    || responseBody.contains("{\"contexts\":{\"application") //mappings
                    || responseBody.contains("{\"request\":{\"type\":\"version\"}") // jolokia
                    || responseBody.contains("{\"traces\":[{\"timestamp\"")){// httptrace
                BurpExtender.tags.add(
                        this.getScannerName(),
                        this.burpAnalyzedRequest.getUrl(response).toString(),
                        this.burpAnalyzedRequest.getStatusCode(response) + "",
                        "[+] found actuator leak",
                        response);
                break;
            }
        }
    }

    public class ActuatorPayload{
        public List<String> expList;
        public ActuatorPayload(String requestURI){
            List<String> payloadList = new ArrayList<>();
            if (requestURI.endsWith("/")) {// http://a.com/ -> / -> + env和 http://a.com/user/ -> / -> + env
                payloadList.add(requestURI + "env");
                payloadList.add(requestURI + "trace");
                payloadList.add(requestURI + "actuator/env");
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
}
