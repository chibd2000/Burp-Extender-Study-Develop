package burp.utils;

import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPatch;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.TrustStrategy;
import org.apache.http.util.EntityUtils;
import org.junit.Test;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.net.URI;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class HttpClientWrapper {

    public SSLConnectionSocketFactory sslsf = null;
    public HttpClientWrapper(){
        this.trustAllCertificate();
    }

    public void trustAllCertificate(){
        try {
            SSLContext sslContext = new SSLContextBuilder().loadTrustMaterial(null, new TrustStrategy() {
                // 信任所有
                public boolean isTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    return true;
                }
            }).build();

            //HostnameVerifier类:  作为主机名验证工具，实质上关闭了主机名验证，它接受任何有效的SSL会话并匹配到目标主机。
            HostnameVerifier hostnameVerifier = NoopHostnameVerifier.INSTANCE;

            this.sslsf = new SSLConnectionSocketFactory(sslContext, hostnameVerifier);

        } catch (NoSuchAlgorithmException | KeyManagementException | KeyStoreException e) {
            e.printStackTrace();
        }
    }

//    public int doGet(String url, String configJson) {
//
//        //创建httpClient客户端
//        this.httpClient = HttpClientBuilder.create().setSSLSocketFactory(this.sslsf).build();
//
//        // 创建请求
//        HttpGet httpGet = new HttpGet(url);
//        // 响应模型
//        CloseableHttpResponse response = null;
//
//        try {
//            // 由客户端执行(发送)Get请求
//            response = httpClient.execute(httpGet);
//        } catch (Exception e) {
//            e.printStackTrace();
//        } finally {
//            try {
//                // 释放资源
//                if (httpClient != null) {
//                    httpClient.close();
//                }
//                if (response != null) {
//                    response.close();
//                }
//            } catch (IOException e) {
//                e.printStackTrace();
//            }
//        }
//
//        return response != null ? response.getStatusLine().getStatusCode() : 500;
//    }

    public String doGet(String url, Map<String, String> param) {
        // 创建Httpclient对象
        CloseableHttpClient httpclient = HttpClientBuilder.create().setSSLSocketFactory(this.sslsf).build();

        String resultString = "";
        CloseableHttpResponse response = null;
        try {
            // 创建uri
            URIBuilder builder = new URIBuilder(url);
            if (param != null) {
                for (String key : param.keySet()) {
                    builder.addParameter(key, param.get(key));
                }
            }
            URI uri = builder.build();

            // 创建http GET请求
            HttpGet httpGet = new HttpGet(uri);

            // 执行请求
            response = httpclient.execute(httpGet);
            // 判断返回状态是否为200
            if (response.getStatusLine().getStatusCode() == 200) {
                resultString = EntityUtils.toString(response.getEntity(), "UTF-8");
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (response != null) {
                    response.close();
                }
                httpclient.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        return resultString;
    }

    /**
     * @Auther: gengshuai@cetiti.com
     * @Description: 带参数和请求头的GET请求
     * @Param: [url, param, header]
     * @Return: java.lang.String
     * @Create: 2018-9-25 20:09
     */
    public String doGet(String url, Map<String, String> param, Map<String, String> header) {
        // 创建Httpclient对象
        CloseableHttpClient httpclient = HttpClientBuilder.create().setSSLSocketFactory(this.sslsf).build();

        String resultString = "";
        CloseableHttpResponse response = null;
        try {
            // 创建uri
            URIBuilder builder = new URIBuilder(url);
            if (param != null) {
                for (String key : param.keySet()) {
                    builder.addParameter(key, param.get(key).toString());
                }
            }
            URI uri = builder.build();

            // 创建http GET请求
            HttpGet httpGet = new HttpGet(uri);

            if (header != null) {
                for (String key : header.keySet()) {
                    httpGet.setHeader(key, header.get(key).toString());
                }
            }

            // 执行请求
            response = httpclient.execute(httpGet);
            // 判断返回状态是否为200
            if (response.getStatusLine().getStatusCode() == 200) {
                resultString = EntityUtils.toString(response.getEntity(), "UTF-8");
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (response != null){
                    response.close();
                }
                httpclient.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        return resultString;
    }

    /**
     * @Auther: gengshuai@cetiti.com
     * @Description: 无参GET请求
     * @Param: [url]
     * @Return: java.lang.String
     * @Create: 2018-9-21 9:05
     */
    public String doGet(String url) {
        return doGet(url, null);
    }

    /**
     * @Auther: gengshuai@cetiti.com
     * @Description: application/x-www-form-urlencoded编码方式带参POST请求
     * @Param: [url, param]
     * @Return: java.lang.String
     * @Create: 2018-9-21 9:05
     */
    public String doPost(String url, Map<String, String> param) {
        // 创建Httpclient对象
        CloseableHttpClient httpClient = HttpClientBuilder.create().setSSLSocketFactory(this.sslsf).build();
        CloseableHttpResponse response = null;
        String resultString = "";
        try {
            // 创建Http Post请求
            HttpPost httpPost = new HttpPost(url);
            // 创建参数列表
            if (param != null) {
                List<NameValuePair> paramList = new ArrayList();
                for (String key : param.keySet()) {
                    paramList.add(new BasicNameValuePair(key, param.get(key)));
                }
                // 模拟表单
                UrlEncodedFormEntity entity = new UrlEncodedFormEntity(paramList,"utf-8");
                httpPost.setEntity(entity);
            }
            // 执行http请求
            response = httpClient.execute(httpPost);
            resultString = EntityUtils.toString(response.getEntity(), "utf-8");
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (response != null){
                    response.close();
                }
                httpClient.close();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }

        return resultString;
    }

    /**
     * @Auther: gengshuai@cetiti.com
     * @Description: application/x-www-form-urlencoded编码方式带参数和请求头的POST请求
     * @Param: [url, param, header]
     * @Return: java.lang.String
     * @Create: 2018-9-27 14:54
     */
    public String doPost(String url, Map<String, String> param, Map<String, String> header) {
        // 创建Httpclient对象
        CloseableHttpClient httpClient = HttpClientBuilder.create().setSSLSocketFactory(this.sslsf).build();
        CloseableHttpResponse response = null;
        String resultString = "";
        try {
            // 创建Http Post请求
            HttpPost httpPost = new HttpPost(url);

            //添加请求头信息
            if (header != null) {
                for (String key : header.keySet()) {
                    httpPost.setHeader(key, header.get(key).toString());
                }
            }
            // 创建参数列表
            if (param != null) {
                List<NameValuePair> paramList = new ArrayList();
                for (String key : param.keySet()) {
                    paramList.add(new BasicNameValuePair(key, param.get(key)));
                }
                // 模拟表单
                UrlEncodedFormEntity entity = new UrlEncodedFormEntity(paramList,"utf-8");
                httpPost.setEntity(entity);
            }
            // 执行http请求
            response = httpClient.execute(httpPost);
            resultString = EntityUtils.toString(response.getEntity(), "utf-8");
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (response != null){
                    response.close();
                }
                httpClient.close();

            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        return resultString;
    }

    /**
     * @Auther: gengshuai@cetiti.com
     * @Description: application/x-www-form-urlencoded编码方式无参POST请求
     * @Param: [url]
     * @Return: java.lang.String
     * @Create: 2018-9-21 9:10
     */
    public String doPost(String url) {
        return doPost(url, null);
    }

    /**
     * @Auther: gengshuai@cetiti.com
     * @Description: application/json编码方式POST请求
     * @Param: [url, json]
     * @Return: java.lang.String
     * @Create: 2018-9-21 9:11
     */
    public String doPostJson(String url, String json) {
        // 创建Httpclient对象
        CloseableHttpClient httpClient = HttpClientBuilder.create().setSSLSocketFactory(this.sslsf).build();
        CloseableHttpResponse response = null;
        String resultString = "";
        try {
            // 创建Http Post请求
            HttpPost httpPost = new HttpPost(url);
            // 创建请求内容
            StringEntity entity = new StringEntity(json, ContentType.APPLICATION_JSON);
            httpPost.setEntity(entity);
            // 执行http请求
            response = httpClient.execute(httpPost);
            resultString = EntityUtils.toString(response.getEntity(), "utf-8");
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (response != null){
                    response.close();
                }
                httpClient.close();

            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }

        return resultString;
    }

    /**
     * @Auther: gengshuai@cetiti.com
     * @Description: application/json编码方式带请求头POST请求
     * @Param: [url, json, header]
     * @Return: java.lang.String
     * @Create: 2018-9-27 15:19
     */
    public String doPostJson(String url, String json, Map<String, String> header) {
        // 创建Httpclient对象
        CloseableHttpClient httpClient = HttpClientBuilder.create().setSSLSocketFactory(this.sslsf).build();
        CloseableHttpResponse response = null;
        String resultString = "";
        try {
            // 创建Http Post请求
            HttpPost httpPost = new HttpPost(url);

            //添加请求头信息
            if (header != null) {
                for (String key : header.keySet()) {
                    httpPost.setHeader(key, header.get(key).toString());
                }
            }

            // 创建请求内容
            StringEntity entity = new StringEntity(json, "utf-8");
            httpPost.setEntity(entity);
            // 执行http请求
            response = httpClient.execute(httpPost);
            resultString = EntityUtils.toString(response.getEntity(), "utf-8");
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (response != null){
                    response.close();
                }
                httpClient.close();

            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        return resultString;
    }

    public int doPatchJson(String url, String json, Map<String, String> header) {
        // 创建Httpclient对象
        CloseableHttpClient httpClient = HttpClientBuilder.create().setSSLSocketFactory(this.sslsf).build();
        CloseableHttpResponse response = null;
        try {
            // 创建Http Post请求
            HttpPatch httpPatch = new HttpPatch(url);

            //添加请求头信息
            if (header != null) {
                for (String key : header.keySet()) {
                    httpPatch.setHeader(key, header.get(key).toString());
                }
            }

            // 创建请求内容
            StringEntity entity = new StringEntity(json, "utf-8");
            httpPatch.setEntity(entity);

            // 执行http请求
            response = httpClient.execute(httpPatch);
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (response != null){
                    response.close();
                }
                httpClient.close();

            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        return response.getStatusLine().getStatusCode();
    }

    @Test
    public void test01(){
        HttpClientWrapper httpClientWrapper = new HttpClientWrapper();
        String s = httpClientWrapper.doGet("https://150.158.186.39:3443", null);
        System.out.println(s);
    }
}
