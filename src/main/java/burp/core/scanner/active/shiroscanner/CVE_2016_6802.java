package burp.core.scanner.active.shiroscanner;

public class CVE_2016_6802 {
    public String requestURI;

    CVE_2016_6802(String requestURI){
        // CVE_2016_6802
        if (!requestURI.endsWith("/")){
            this.requestURI = requestURI + "/";
        }else{
            this.requestURI = "/xxxxxxxxxxxxxxxxxxxxxx";
        }
    }

    public String getRequestURI() {
        return requestURI;
    }

    @Override
    public String toString() {
        return "CVE_2016_6802";
    }
}
