package burp.core.scanner.passive;

import org.junit.Test;

public class TestCode {
    @Test
    public void test01(){
        String requestUrl = "/aaa";
        String requestUrlRoot = requestUrl.endsWith("/") ? requestUrl : requestUrl.substring(0,requestUrl.lastIndexOf("/")+1);
        System.out.println(requestUrlRoot);
    }

    @Test
    public void test02() {
        String requestURI = "/asdasd/";
        if (requestURI.endsWith("/")) {// http://a.com/ -> / -> + env和 http://a.com/user/ -> / -> + env
            requestURI = requestURI + "env";
        } else {
            requestURI = requestURI + "/env";
        }
        System.out.println(requestURI);
    }

    @Test
    public void test03() {
        String host = "a.b.c.www.baidu.com";
        int i = host.lastIndexOf(".");
        String host1 = host.substring(0,i);
        int j = host1.lastIndexOf(".");
        String host2 = host1.substring(j+1);
    }
}
