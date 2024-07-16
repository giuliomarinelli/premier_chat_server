package backend.app.premier_chat.security;

import backend.app.premier_chat.Models.enums.EncodeType;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;

@Component
public class SecurityUtils {

    public String keyGenerator(int bytes, EncodeType encodeType) {

        String encodedString = "";

        SecureRandom secureRandom = new SecureRandom();
        byte[] key = new byte[bytes];
        secureRandom.nextBytes(key);

        switch (encodeType) {
            case BASE_32 -> {
                Base32 base32 = new Base32();
                encodedString = base32.encodeToString(key);
            }
            case BASE_64 -> {
                Base64 base64 = new Base64();
                encodedString = base64.encodeToString(key);
            }
            case HEX -> encodedString = Hex.encodeHexString(key);
        }

        return encodedString;

    }

    public String obscureEmail(String email) {

        int i = email.indexOf("@");
        // Gestire l'eccezione nel caso in cui i = -1
        String visible = email.substring(i - 2, i);
        return "*".repeat(i - 3) + visible + email.substring(i);

    }


}
