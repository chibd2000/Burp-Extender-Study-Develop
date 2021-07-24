package burp.core.scanner.active.bugscanner;

import burp.BurpExtender;
import burp.BurpScanIssue;
import burp.utils.HttpClientWrapper;
import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import org.junit.Test;

import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Properties;

public class TestCode {

    @Test
    public void test01() throws FileNotFoundException {
        InputStream in = new BufferedInputStream(new FileInputStream("db.properties"));
        Properties p = new Properties();
        try {
            p.load(in);
        } catch (IOException e) {
            e.printStackTrace();
        }
        System.out.println(p.getProperty("version"));
    }


    @Test
    public void testJson(){
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("name","tom");
        jsonObject.put("age",20);

        JSONArray jsonArray = new JSONArray();
        JSONObject jsonArrayObject1 = new JSONObject();
        jsonArrayObject1.put("name","alibaba");
        jsonArrayObject1.put("info","www.alibaba.com");
        JSONObject jsonArrayObject2 = new JSONObject();
        jsonArrayObject2.put("name","baidu");
        jsonArrayObject2.put("info","www.baidu.com");

        jsonArray.add(jsonArrayObject1);
        jsonArray.add(jsonArrayObject2);

        jsonObject.put("sites",jsonArray);

        System.out.println(jsonObject);
    }

    @Test
    public void test02(){
        JSONObject taskObject = new JSONObject();
        String addTargetUrl = "https://150.158.186.39:3443".concat("/api/v1/targets/add");


        JSONObject targetsObject = new JSONObject();
        targetsObject.put("address", addTargetUrl);
        targetsObject.put("description", "burp-add");

        JSONArray targetsArray = new JSONArray();
        targetsArray.add(targetsObject);

        taskObject.put("targets", targetsArray);

        JSONArray nullArray = new JSONArray();

        taskObject.put("groups", nullArray);

        System.out.println(taskObject);
    }

    @Test
    public void test03(){
        URI uri = null;
        try {
            uri = new URI("http://www.baidu.com/");
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
        assert uri != null;
        String s = uri.toString();
        System.out.println(s);
        boolean b = s.endsWith("/");
        System.out.println(b);

    }

    @Test
    public void ttttt(){
        String json = "{\"groups\":[],\"targets\":[{\"address\":\"http://testphp.vulnweb.com/\",\"description\":\"burp-add\"}]}";
        HttpClientWrapper httpClientWrapper = new HttpClientWrapper();
        String s1 = httpClientWrapper.doPostJson("https://150.158.186.39:3443/api/v1/targets/add", json);
        System.out.println(s1);
    }
    @Test
    public void wwtwt(){
        String[] commonHeaders = {"Cache-Control", "Connection", "Transfer-Encoding", "Upgrade",
                "Via", "Warning", "Accept", "Accept-Charset", "Accept-Encoding",
                "Except", "Host", "if-Match", "if-Modified-Since", "Range", "Referer",
                "TE", "User-Agent", "Allow", "Content-Encoding", "Content-Language",
                "Content-Length", "Content-Location", "Content-MD5", "Content-Range",
                "Content-Type", "Expires", "Last-Modified"};
        for (String commonHeader : commonHeaders) {
            System.out.println(commonHeader);
        }
    }
}
