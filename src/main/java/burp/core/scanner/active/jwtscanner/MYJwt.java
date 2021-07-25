package burp.core.scanner.active.jwtscanner;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.SignatureGenerationException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class MYJwt {
    public String base64header;
    public String headerJson;
    public String base64Pyload;
    public String payloadJson;
    public String base64Sign;
    public String sign;
    public String jwtContent;

    public MYJwt(String jwtContent){
        this.jwtContent = jwtContent;
        this.jwtInit();
    }

    public void jwtInit(){
        String[] parts = JWTUtils.splitToken(this.jwtContent);

        this.base64header = parts[0];
        this.base64Pyload = parts[1];
        this.base64Sign = parts[2];

        try {
            this.headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
            this.payloadJson = new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8);
        } catch (NullPointerException e) {
            throw new JWTDecodeException("The UTF-8 Charset isn't initialized.", e);
        } catch (IllegalArgumentException e){
            throw new JWTDecodeException("The input is not a valid base 64 encoded string.", e);
        }
    }

    public String getHeaderJson() {
        return headerJson;
    }

    public void setHeaderJson(String headerJson) {
        this.headerJson = headerJson;
    }

    public String getPayloadJson() {
        return payloadJson;
    }

    public void setPayloadJson(String payloadJson) {
        this.payloadJson = payloadJson;
    }

    public String getSign() {
        return sign;
    }

    public void setSign(String sign) {
        this.sign = sign;
    }

    public String sign(Algorithm algorithm) throws SignatureGenerationException {
        String header = Base64.getUrlEncoder().withoutPadding().encodeToString(this.headerJson.getBytes(StandardCharsets.UTF_8));
        String payload = Base64.getUrlEncoder().withoutPadding().encodeToString(this.payloadJson.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = algorithm.sign(header.getBytes(StandardCharsets.UTF_8), payload.getBytes(StandardCharsets.UTF_8));
        String signature = Base64.getUrlEncoder().withoutPadding().encodeToString((signatureBytes));
        return String.format("%s.%s.%s", header, payload, signature);
    }
}
