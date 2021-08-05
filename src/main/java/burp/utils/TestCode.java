package burp.utils;

import org.junit.Test;

import java.util.ArrayList;
import java.util.Map;

public class TestCode {
    @Test
    public void test01(String[] args) {

        UrlRepeatMap<String, Integer> domainNameMap1 = UrlRepeatMap.getUrlRepeatMap();
        domainNameMap1.add("aaaaa");
        System.out.println(domainNameMap1.size());

        UrlRepeatMap<String, Integer> domainNameMap2 = UrlRepeatMap.getUrlRepeatMap();
        domainNameMap1.add("bbbbb");
        System.out.println(domainNameMap2.size());

        UrlRepeatMap<String, Integer> domainNameMap3 = UrlRepeatMap.getUrlRepeatMap();
        domainNameMap1.add("aaaaa");
        System.out.println(domainNameMap3.size());
    }
}
