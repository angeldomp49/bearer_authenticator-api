package org.makechtec.web.authentication_gateway.bearer.token;

import com.google.common.hash.Hashing;
import org.makechtec.software.json_tree.ObjectLeaf;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class TokenBuilder {

    private final SignaturePrinter signaturePrinter = new SignaturePrinter();
    private String encodedHeader;
    private String encodedPayload;
    private String signature;

    private TokenBuilder(){}

    public TokenBuilder header(ObjectLeaf header){
        this.encodedHeader = encodeToBase64(header.getLeafValue());
        return this;
    }

    public TokenBuilder payload(ObjectLeaf payload){
        this.encodedPayload = encodeToBase64(payload.getLeafValue());
        return this;
    }

    public TokenBuilder sign(String secretKey){

        var message = this.encodedHeader +'.' + this.encodedPayload + '.' + secretKey;

        this.signature = signaturePrinter.sign(message);

        return this;
    }

    public String build(){
        return this.encodedHeader + '.' + this.encodedPayload + '.' + this.signature;
    }

    public static TokenBuilder builder(){
        return new TokenBuilder();
    }

    private String encodeToBase64(String original){
        return new String(
                Base64.getEncoder()
                        .encode(original.getBytes())
        );
    }

}
