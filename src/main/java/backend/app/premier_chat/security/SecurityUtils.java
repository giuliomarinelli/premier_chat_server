package backend.app.premier_chat.security;

import backend.app.premier_chat.Models.Dto.outputDto.JotpWrapperOutputDTO;
import backend.app.premier_chat.Models.configuration.JotpConfiguration;
import backend.app.premier_chat.Models.enums.EncodeType;
import backend.app.premier_chat.exception_handling.InternalServerErrorException;
import com.amdelamar.jotp.OTP;
import com.amdelamar.jotp.type.Type;
import jdk.jfr.Timestamp;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

@Component
@Configuration
public class SecurityUtils {

    @Autowired
    private JotpConfiguration jotpConfiguration;

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

    public String generateJotpRandomSecret() {
        return OTP.randomBase32(jotpConfiguration.getBytesNumberForBase32Secret());
    }

    public JotpWrapperOutputDTO generateJotpTOTP(String base32Secret) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        long now = System.currentTimeMillis();
        long exp = now + jotpConfiguration.getPeriod() * 1000L;
        String hexTime = OTP.timeInHex(now, jotpConfiguration.getPeriod());
        String TOTP = OTP.create(base32Secret, hexTime, jotpConfiguration.getDigits(), Type.TOTP);
        return new JotpWrapperOutputDTO(TOTP, now, exp);
    }

    public boolean verifyJotpTOTP(String base32Secret, String TOTP) {
        try {
            String hexTime = OTP.timeInHex(System.currentTimeMillis(), jotpConfiguration.getPeriod());
            return OTP.verify(base32Secret, hexTime, TOTP, jotpConfiguration.getDigits(), Type.TOTP);
        } catch (NoSuchAlgorithmException | InvalidKeyException | IOException e) {
            throw new InternalServerErrorException("Error in TOTP verification. " + e.getMessage());
        }
    }


}
