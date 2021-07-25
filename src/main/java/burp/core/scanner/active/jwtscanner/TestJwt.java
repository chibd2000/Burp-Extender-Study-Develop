package burp.core.scanner.active.jwtscanner;

import com.alibaba.fastjson.JSONObject;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.impl.JWTParser;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Header;
import com.auth0.jwt.interfaces.Payload;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class TestJwt {
    @Test
    public void test01(){
        String jwtContent = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        String[] parts = JWTUtils.splitToken(jwtContent);
        String headerJson;
        String payloadJson;
        try {
            headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        } catch (NullPointerException e) {
            throw new JWTDecodeException("The UTF-8 Charset isn't initialized.", e);
        } catch (IllegalArgumentException e){
            throw new JWTDecodeException("The input is not a valid base 64 encoded string.", e);
        }

//        String sign = JWTUtils.sign(headerJson, payloadJson, Algorithm.none());
//        System.out.println(sign);
    }

    @Test
    public void test02(){
        String jwtContent = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

        List<String> checkJwtList = new ArrayList<>();
        for (IJwtConstant.NoneFlag value : IJwtConstant.NoneFlag.values()) {
            MYJwt myJwt = new MYJwt(jwtContent);
            JSONObject jsonObject = JSONObject.parseObject(myJwt.getHeaderJson());
            jsonObject.replace("alg", value);
            myJwt.setHeaderJson(jsonObject.toJSONString());
            String b64JwtHeader = myJwt.sign(Algorithm.none());
            checkJwtList.add(b64JwtHeader);
        }

        for (String s : checkJwtList) {
            System.out.println(s);
        }
    }
}
