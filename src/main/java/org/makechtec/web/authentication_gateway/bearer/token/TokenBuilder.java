package org.makechtec.web.authentication_gateway.bearer.token;

import org.makechtec.software.json_tree.ObjectLeaf;

import java.util.Base64;

public class TokenBuilder {

    private final SignaturePrinter signaturePrinter;
    private String encodedHeader;
    private String encodedPayload;
    private String signature;

    private TokenBuilder(SignaturePrinter signaturePrinter) {
        this.signaturePrinter = signaturePrinter;
    }

    public static TokenBuilder builder(SignaturePrinter signaturePrinter) {
        return new TokenBuilder(signaturePrinter);
    }

    public TokenBuilder header(ObjectLeaf header) {
        this.encodedHeader = encodeToBase64(header.getLeafValue());
        return this;
    }

    public TokenBuilder payload(ObjectLeaf payload) {
        this.encodedPayload = encodeToBase64(payload.getLeafValue());
        return this;
    }

    public TokenBuilder sign() {

        var message = this.encodedHeader + '.' + this.encodedPayload;

        this.signature = signaturePrinter.sign(message);

        return this;
    }

    public String build() {
        return this.encodedHeader + '.' + this.encodedPayload + '.' + this.signature;
    }

    private String encodeToBase64(String original) {
        return new String(
                Base64.getEncoder()
                        .encode(original.getBytes())
        );
    }

}
