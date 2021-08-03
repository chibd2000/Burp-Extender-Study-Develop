package burp.core.scanner.active.jwtscanner;


import burp.IHttpRequestResponse;

/*
* 无签名验证
* */
public class NoVerifyLeak {

    public String exp;

    public NoVerifyLeak(IHttpRequestResponse httpRequestResponse) {
        MYJwt myJwt = new MYJwt(JWTUtils.verifyJwt(httpRequestResponse));
        this.exp = myJwt.getBase64header() + "." + myJwt.getBase64Pyload() + ".";
    }

    public String getExp() {
        return exp;
    }

    @Override
    public String toString() {
        return "NoVerifyLeak";
    }
}
