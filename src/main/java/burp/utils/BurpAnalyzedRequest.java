package burp.utils;

import burp.*;
import burp.core.scanner.active.jwtscanner.IJwtConstant;
import com.alibaba.fastjson.JSONObject;

import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/*
* 解析BURP的request和response数据
* */
public class BurpAnalyzedRequest {

    private IExtensionHelpers helpers;
    public PrintWriter stdout;

    public BurpAnalyzedRequest(){
        this.helpers = BurpExtender.callbacks.getHelpers();
        this.stdout = new PrintWriter(BurpExtender.callbacks.getStdout(), true);
    }

    public String getRequestContent(IHttpRequestResponse requestResponse){
        return new String(requestResponse.getRequest());
    }

    public URL getUrl(IHttpRequestResponse requestResponse) {
        IRequestInfo requestInfo = helpers.analyzeRequest(requestResponse.getHttpService(), requestResponse.getRequest());
        return requestInfo.getUrl();
    }

    public int getStatusCode(IHttpRequestResponse requestResponse) {
        IResponseInfo iRequestInfo = this.helpers.analyzeResponse(requestResponse.getResponse());
        return iRequestInfo.getStatusCode();
    }

    public byte[] getRequestBody(IHttpRequestResponse requestResponse){
        IRequestInfo requestInfo = this.helpers.analyzeRequest(requestResponse.getRequest());
        try {
            String requestBodyString = new String(requestResponse.getRequest());
            return requestBodyString.substring(requestInfo.getBodyOffset()).getBytes();
        } catch (Exception e) {
            return new byte[]{};
        }
    }

    public int getRequestBodySize(IHttpRequestResponse requestResponse){
        return requestResponse.getRequest().length;
    }

    public byte[] getResponseBody(IHttpRequestResponse requestResponse){
        IResponseInfo responseInfo = this.helpers.analyzeResponse(requestResponse.getResponse());
        try {
            String responseBodyString = new String(requestResponse.getResponse());
            return responseBodyString.substring(responseInfo.getBodyOffset()).getBytes();
        } catch (Exception e) {
            return new byte[]{};
        }
    }

    public int getResponseBodySize(IHttpRequestResponse requestResponse){
        return this.getResponseBody(requestResponse).length;
    }

    public String getJwt(IHttpRequestResponse requestResponse){
        String jwt = "";
        Pattern pattern = Pattern.compile(IJwtConstant.regexpJwtPattern);
        try {
            Matcher matcher = pattern.matcher(this.getRequestContent(requestResponse));
            if (matcher.find()){
                jwt = matcher.group(0);
            }
        }catch (Exception e) {
            return "";
        }

        return jwt;
    }

    public boolean getJwtFlag(IHttpRequestResponse requestResponse){
        boolean flag = false;
        Pattern pattern = Pattern.compile(IJwtConstant.regexpJwtPattern);
        Matcher matcher = pattern.matcher(this.getRequestContent(requestResponse));
        if (matcher.find()){
            flag = true;
        }
        return flag;
    }

    public String getRequestDomain(IHttpRequestResponse baseRequestResponse){
        String baseRequestProtocol = baseRequestResponse.getHttpService().getProtocol();
        String baseRequestHost = baseRequestResponse.getHttpService().getHost();
        int baseRequestPort = baseRequestResponse.getHttpService().getPort();
        if (baseRequestPort == 80 || baseRequestPort == 443){
            return baseRequestProtocol + "://" + baseRequestHost;
        }else{
            return baseRequestProtocol + "://" + baseRequestHost + ":" + baseRequestPort;
        }
    }

    public String getRequestPath(IHttpRequestResponse baseRequestResponse){
        return this.helpers.analyzeRequest(baseRequestResponse).getUrl().getPath();
    }

    public List<IParameter> getAllParamters(IHttpRequestResponse requestResponse) {
        return this.helpers.analyzeRequest(requestResponse.getRequest()).getParameters();
    }

    public String getMethod(IHttpRequestResponse requestResponse) {
        IRequestInfo requestInfo = this.helpers.analyzeRequest(requestResponse.getRequest());
        return requestInfo.getMethod();
    }

    public byte[] buildHttpRequest(IHttpRequestResponse requestResponseTemplate, URL newUrl) {
        byte[] mockRequset = this.helpers.buildHttpRequest(newUrl);
        List<IParameter> parameters = this.getAllParamters(requestResponseTemplate);
        for (IParameter parameter: parameters) {
            mockRequset = this.helpers.addParameter(mockRequset, parameter);
        }
        return mockRequset;
    }

    public byte[] addOrUpdateCookie(IHttpRequestResponse requestResponse, String key, String value) {
        IParameter targetParam = this.helpers.getRequestParameter(requestResponse.getRequest(), key);
        IParameter newParam = this.helpers.buildParameter(key, value, IParameter.PARAM_COOKIE);

        if (targetParam != null && targetParam.getType() == IParameter.PARAM_COOKIE){
            return this.helpers.updateParameter(requestResponse.getRequest(), newParam);
        } else {
            return this.helpers.addParameter(requestResponse.getRequest(), newParam);
        }
    }

    public List<String> getCookies(IHttpRequestResponse requestResponse){
        List<IParameter> allParamters = this.getAllParamters(requestResponse);
        List<String> cookiesList = new ArrayList<>();
        String url = this.getRequestDomain(requestResponse);
        for (IParameter targetParam : allParamters) {
            if (targetParam != null && targetParam.getType() == IParameter.PARAM_COOKIE){
                JSONObject jsonObject = new JSONObject();
                String cookie = targetParam.getName() + "=" + targetParam.getValue();
                jsonObject.put("url", url);
                jsonObject.put("cookie", cookie);
                cookiesList.add(jsonObject.toJSONString());
            }
        }
        return cookiesList;
    }

}
