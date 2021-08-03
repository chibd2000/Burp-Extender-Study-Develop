package burp.core.scanner.active.jwtscanner;

import burp.IHttpRequestResponse;
import com.auth0.jwt.exceptions.JWTDecodeException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/*
* JWT工具类
* */
public class JWTUtils {
    public static String verifyJwt(IHttpRequestResponse requestResponse){
        String jwt = "";
        Pattern pattern = Pattern.compile(IJWTConstant.regexpJwtPattern);
        try {
            Matcher matcher = pattern.matcher(new String(requestResponse.getRequest()));
            if (matcher.find()){
                jwt = matcher.group(0);
            }
        }catch (Exception e) {
            return "";
        }
        return jwt;
    }

    public static boolean getJwtFlag(IHttpRequestResponse requestResponse){
        boolean flag = false;
        Pattern pattern = Pattern.compile(IJWTConstant.regexpJwtPattern);
        Matcher matcher = pattern.matcher(new String(requestResponse.getRequest()));
        if (matcher.find()){
            flag = true;
        }
        return flag;
    }

    static String[] splitToken(String token) throws JWTDecodeException {
        String[] parts = token.split("\\.");
        if (parts.length == 2 && token.endsWith(".")) {
            //Tokens with alg='none' have empty String as Signature.
            parts = new String[]{parts[0], parts[1], ""};
        }
        if (parts.length != 3) {
            throw new JWTDecodeException(String.format("The token was expected to have 3 parts, but got %s.", parts.length));
        }
        return parts;
    }

    static String decodeJwt(String jwtContent) throws JWTDecodeException {
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
//        return sign;
        return null;
    }
}
