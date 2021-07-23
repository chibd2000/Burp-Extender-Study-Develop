package burp.utils;

import java.util.Map;

public class TestCode {
    public static void main(String[] args) {

        DomainNameRepeat<String, Integer> domainNameMap1 = DomainNameRepeat.getDomainNameMap();
        domainNameMap1.add("aaaaa");
        System.out.println(domainNameMap1.size());

        DomainNameRepeat<String, Integer> domainNameMap2 = DomainNameRepeat.getDomainNameMap();
        domainNameMap1.add("bbbbb");
        System.out.println(domainNameMap2.size());

        DomainNameRepeat<String, Integer> domainNameMap3 = DomainNameRepeat.getDomainNameMap();
        domainNameMap1.add("aaaaa");
        System.out.println(domainNameMap3.size());
    }
}
