package org.makechtec.web.authentication_gateway.password;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.bouncycastle.util.encoders.Hex;
import org.makechtec.web.authentication_gateway.app.properties.CrypographyInformation;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Arrays;

public class PasswordHasher {

    private final CrypographyInformation crypographyInformation;
    private final SaltGenerator saltGenerator = new SaltGenerator();
    private final int HASH_LENGTH_BYTES = 64;

    public PasswordHasher(CrypographyInformation crypographyInformation) {
        this.crypographyInformation = crypographyInformation;
    }

    public byte[] rawHash(String password) {
        var salt = saltGenerator.generate();
        return rawHash(password, salt);
    }

    public byte[] rawHash(String password, byte[] salt) {

        var params =
                new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                        .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                        .withMemoryAsKB(crypographyInformation.getArgon2SettingsMemory())
                        .withIterations(crypographyInformation.getArgon2SettingsIterations())
                        .withParallelism(crypographyInformation.getArgon2SettingsParallelismFactor())
                        .withSalt(salt)
                        .build();

        var hashGenerator = new Argon2BytesGenerator();
        hashGenerator.init(params);

        var hash = new byte[HASH_LENGTH_BYTES];

        hashGenerator.generateBytes(password.toCharArray(), hash);

        return mergeArrays(hash, salt);
    }

    public String hash(String password){
        return new String(Hex.encode(rawHash(password)));
    }

    public boolean matches(String originalUnhashed, String hashedToCompare){
        var storedHash = Hex.decode(hashedToCompare);
        byte[] realStoredHash = Arrays.copyOfRange(storedHash, 0, 64);
        byte[] salt = Arrays.copyOfRange(storedHash, 64, storedHash.length);

        System.out.println("realStoredHash: "+new String(Hex.encode(realStoredHash)));
        System.out.println("salt: "+new String(Hex.encode(salt)));
        System.out.println("reformed: "+new String(Hex.encode(rawHash(originalUnhashed, salt))));

        return MessageDigest.isEqual(rawHash(originalUnhashed, salt), storedHash);
    }

    private static byte[] mergeArrays(byte[] array1, byte[] array2) {
        ByteBuffer buffer = ByteBuffer.allocate(array1.length + array2.length);
        buffer.put(array1);
        buffer.put(array2);
        return buffer.array();
    }


}
