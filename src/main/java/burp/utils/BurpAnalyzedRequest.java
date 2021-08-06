package burp.utils;

import burp.*;
import com.alibaba.fastjson.JSONObject;

import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/*
* 解析BURP的request和response数据工具类
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

    public String getResponseContent(IHttpRequestResponse requestResponse){
        return new String(requestResponse.getResponse());
    }

    public URL getUrl(IHttpRequestResponse requestResponse) {
        IRequestInfo requestInfo = helpers.analyzeRequest(requestResponse.getHttpService(), requestResponse.getRequest());
        return requestInfo.getUrl();
    }

    public int getStatusCode(IHttpRequestResponse requestResponse) {
        IResponseInfo iRequestInfo = this.helpers.analyzeResponse(requestResponse.getResponse());
        return iRequestInfo.getStatusCode();
    }

    public List<String> getResponseHeaders(IHttpRequestResponse requestResponse) {
        IResponseInfo iRequestInfo = this.helpers.analyzeResponse(requestResponse.getResponse());
        return iRequestInfo.getHeaders();
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

/*  放到了JWTUtils类
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
*/

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

    public String getRequestURI(IHttpRequestResponse baseRequestResponse){
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

    /*for awvs*/
    public List<String> getCookies(IHttpRequestResponse requestResponse){
        List<IParameter> allParamters = this.getAllParamters(requestResponse);
        List<String> cookiesList = new ArrayList<>();
        int getNum = 0;
        String url = this.getRequestDomain(requestResponse);
        for (IParameter targetParam : allParamters) {
            if (targetParam != null && targetParam.getType() == IParameter.PARAM_COOKIE){
                if (getNum == 10){
                    break;
                }
                JSONObject jsonObject = new JSONObject();
                String cookie = targetParam.getName() + "=" + targetParam.getValue();
                jsonObject.put("url", url);
                jsonObject.put("cookie", cookie);
                cookiesList.add(jsonObject.toJSONString());
                getNum++;
            }
        }

        return cookiesList;
    }

    /*for awvs*/
    public List<String> getCustomHeaders(IHttpRequestResponse requestResponse){
        List<String> headersList = new ArrayList<>();
        IRequestInfo RequestInfo = this.helpers.analyzeRequest(requestResponse);
        List<String> headers = RequestInfo.getHeaders();
        String[] commonHeaders = {"HTTP/1.1", "Cache-Control", "Connection", "Transfer-Encoding", "Upgrade",
                "Via", "Warning", "Accept", "Accept-Charset", "Accept-Encoding",
                "Except", "Host", "if-Match", "if-Modified-Since", "Range", "Referer",
                "TE", "User-Agent", "Allow", "Content-Encoding", "Content-Language",
                "Content-Length", "Content-Location", "Content-MD5", "Content-Range",
                "Content-Type", "Expires", "Last-Modified", "Cookie", "If-None-Match"};
        for (String currentHeader : headers) {

            boolean flag = false;
            for (String commonHeader : commonHeaders) {
                if (currentHeader.toLowerCase().contains(commonHeader.toLowerCase()))
                {
                    // 如果到这里，那说明当前字段就是通用字段，那这次循环就直接不走了，break掉
                    flag = true;
                    break;
                }
            }
            if (!flag){
                // 如果到了这里，说明上面的通用字段没有匹配到，说明这个字段我们需要用到，也就是有可能是鉴权字段
                headersList.add("\""+ currentHeader.replaceAll("\"", "\\\\\"") + "\"");
            }
        }
        return headersList;
    }

    public String getMethod(IExtensionHelpers helpers, IHttpRequestResponse requestResponse) {
        IRequestInfo requestInfo = helpers.analyzeRequest(requestResponse.getRequest());
        return requestInfo.getMethod();
    }

    /**
     * Only works on GET requests
     * @param helpers
     * @param requestResponse
     * @param appendPath
     * @return try requests
     */
    public ArrayList<URL> addTraversalPaths(IExtensionHelpers helpers, IHttpRequestResponse requestResponse, String appendPath) throws MalformedURLException {
        ArrayList<URL> traversalUrls = new ArrayList<>();
        if (appendPath.startsWith("/")) {
            appendPath = appendPath.substring(1);
        }
        if (this.getMethod(helpers, requestResponse).equals("GET")) {
            URL url = this.getUrl(requestResponse);
            String path = url.getPath();
            if (path.equals("") || path.equals("/")) {
                path = "/a";
            }
            List<String> pathList = Arrays.asList(path.split("/"));
            for(int i=0;i<pathList.size();i++) {
                List<String> temp = pathList.subList(0, i+1);
                String tempPath = String.join("/", temp);
                String tempUrl;
                if (url.getProtocol().equals("http") && url.getPort() == 80) {
                    tempUrl = String.format("%s://%s%s/%s", url.getProtocol(), url.getHost(), tempPath, appendPath);
                } else if (url.getProtocol().equals("https") && url.getPort() == 443) {
                    tempUrl = String.format("%s://%s%s/%s", url.getProtocol(), url.getHost(), tempPath, appendPath);
                } else {
                    tempUrl = String.format("%s://%s:%d%s/%s", url.getProtocol(), url.getHost(), url.getPort(), tempPath, appendPath);
                }
                traversalUrls.add(new URL(tempUrl));
            }
        }
        return traversalUrls;
    }

}
