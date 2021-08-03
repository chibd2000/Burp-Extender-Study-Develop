package burp.core.scanner.active.shiroscanner;

import org.junit.Test;

public class TestShiro {
    @Test
    public void test01(){
        String a = "/aaaa/xxxx";
        int i = a.lastIndexOf("/");
        String before = a.substring(0,i);
        String after = a.substring(i);
        String b = before + "/;" + after;
        System.out.println(b);
    }

    @Test
    public void test02(){
        String a = "/test/admin/info";
        int i = a.indexOf("/");
        String a2 = a.substring(i+1);
        int j = a2.indexOf("/");
        String a3 = a.substring(j+1);
        String a4 = a.substring(i,j+1);
        System.out.println(a4+";"+a3);

    }

    @Test
    public void test03(){
        String a = "/admin/info";
        int i = a.lastIndexOf("/");
        String a2 = a.substring(0,i+1);
        System.out.println(a2);
        String a3 = a.substring(i+1);
        System.out.println(a3);
        System.out.println(a2 + "%3b" + a3);

    }
}
