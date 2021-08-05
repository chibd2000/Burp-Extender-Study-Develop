package burp.utils;

import java.util.HashMap;

/*
* 单例模式
* */
public class UrlRepeatMap<S, I extends Number> extends HashMap<String, Integer> {

    private static UrlRepeatMap<String, Integer> urlRepeatMap = new UrlRepeatMap<String, Integer>();

    private UrlRepeatMap() {

    }

    public static UrlRepeatMap<String, Integer> getUrlRepeatMap(){
        return urlRepeatMap;
    }

    /*增*/
    public void add(String url) {
        if (url == null || url.length() <= 0) {
            throw new IllegalArgumentException("域名不能为空");
        }
        UrlRepeatMap.getUrlRepeatMap().put(url, 1);
    }

    /*删*/
    public void del(String url) {
        if (UrlRepeatMap.getUrlRepeatMap().get(url) != null) {
            UrlRepeatMap.getUrlRepeatMap().remove(url);
        }
    }

    /*查*/
    public boolean check(String url) {
        return UrlRepeatMap.getUrlRepeatMap().get(url) != null;
    }

}
