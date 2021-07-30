package burp.utils;

import java.util.HashMap;

/*
* 单例模式
* */
public class DomainNameRepeat<S, I extends Number> extends HashMap<String, Integer> {

    private static DomainNameRepeat<String, Integer> domainNameMap = new DomainNameRepeat<String, Integer>();

    private DomainNameRepeat() {

    }

    public static DomainNameRepeat<String, Integer> getDomainNameMap(){
        return domainNameMap;
    }

    /*增*/
    public void add(String domainName) {
        if (domainName == null || domainName.length() <= 0) {
            throw new IllegalArgumentException("域名不能为空");
        }

        DomainNameRepeat.getDomainNameMap().put(domainName, 1);
    }

    /*删*/
    public void del(String domainName) {
        if (DomainNameRepeat.getDomainNameMap().get(domainName) != null) {
            DomainNameRepeat.getDomainNameMap().remove(domainName);
        }
    }

    /*查*/
    public boolean check(String domainName) {
        return DomainNameRepeat.getDomainNameMap().get(domainName) != null;
    }

}
