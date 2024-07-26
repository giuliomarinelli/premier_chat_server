package backend.app.premier_chat.debug;


import backend.app.premier_chat.Models.Dto.outputDto.JotpWrapperOutputDTO;
import backend.app.premier_chat.Models.configuration.SecurityCookieConfiguration;
import backend.app.premier_chat.Models.enums.EncodeType;
import backend.app.premier_chat.Models.enums.TokenType;
import backend.app.premier_chat.security.JwtUtils;
import backend.app.premier_chat.security.SecurityUtils;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

@Component
@Order(3)
@Log4j2
public class DebugCmdLineRunner implements CommandLineRunner {

//    private final JwtUtils jwtUtils;
//
//    private final SecurityCookieConfiguration securityCookieConfiguration;
//
//    private final SecurityUtils securityUtils;
//
//    public DebugCmdLineRunner(JwtUtils jwtUtils, SecurityCookieConfiguration securityCookieConfiguration, SecurityUtils securityUtils) {
//        this.jwtUtils = jwtUtils;
//        this.securityCookieConfiguration = securityCookieConfiguration;
//        this.securityUtils = securityUtils;
//    }
//
//    public LocalTime getLocalTimeFromUnixEpochMillis(long unixEpochTimestampMillis) {
//        // Converti il timestamp Unix in millisecondi a un oggetto Instant
//        Instant instant = Instant.ofEpochMilli(unixEpochTimestampMillis);
//
//        // Converti l'oggetto Instant a LocalTime
//        return roundToNearestSecond(instant.atZone(ZoneId.systemDefault()).toLocalTime());
//
//    }
//
//    public LocalTime roundToNearestSecond(LocalTime localTime) {
//        int nanoSeconds = localTime.getNano();
//        if (nanoSeconds >= 500_000_000) {
//            // Arrotonda verso l'alto
//            localTime = localTime.plusSeconds(1);
//        }
//        // Imposta i nanosecondi a zero
//        return localTime.truncatedTo(ChronoUnit.SECONDS);
//    }

    @Override
    public void run(String... args) throws Exception {

//        String token = jwtUtils.generateToken(UUID.randomUUID(), TokenType.ACCESS_TOKEN, false);
//        log.info("ACCESS TOKEN = {}", token);
//
//        jwtUtils.revokeToken(token, TokenType.ACCESS_TOKEN);
//
//        log.info("Is Revoked Token: {}", jwtUtils.isRevokedToken(token, TokenType.ACCESS_TOKEN));
//
//        log.info("Is Token Valid: {}", jwtUtils.verifyToken(token, TokenType.ACCESS_TOKEN, false));
//
//        log.info(jwtUtils.extractJwtUsefulClaims(token, TokenType.ACCESS_TOKEN, false));

//        log.info(securityCookieConfiguration);
//
//        String secret = securityUtils.generateJotpRandomSecret();

//        log.info("TOTP Secret = {}", secret);
//        String _TOTP = securityUtils.generateJotpTOTP(secret);
//        log.info("Generated TOTP = {}", _TOTP);
//        log.info("TOTP Validity = {}", securityUtils.verifyJotpTOTP(secret, _TOTP));
//        log.info("TOTP Validity = {}", securityUtils.verifyJotpTOTP("EGQPZVSHV6QXV7VPMQYFRVE6VVEKNY3M", "936577"));
//
//        JotpWrapperOutputDTO jotpWrapperOutputDTO = securityUtils.generateJotpTOTP("EGQPZVSHV6QXV7VPMQYFRVE6VVEKNY3M");
//
//        log.info(
//                "Codice TOTP = {}. Valido dalle {} alle {}",
//                jotpWrapperOutputDTO.getTOTP(),
//                getLocalTimeFromUnixEpochMillis(jotpWrapperOutputDTO.getGeneratedAt()),
//                getLocalTimeFromUnixEpochMillis(jotpWrapperOutputDTO.getExpiresAt())
//        );
//
//        log.info("SECRET={}", securityUtils.keyGenerator(32, EncodeType.BASE_64));
//        log.info("SECRET={}", securityUtils.keyGenerator(512, EncodeType.BASE_64));

    }

}
