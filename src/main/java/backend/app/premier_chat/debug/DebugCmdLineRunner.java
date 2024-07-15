package backend.app.premier_chat.debug;


import backend.app.premier_chat.Models.enums.TokenType;
import backend.app.premier_chat.security.JwtUtils;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.util.UUID;

//@Component
//@Order(3)
@Log4j2
public class DebugCmdLineRunner implements CommandLineRunner {

    @Autowired
    private JwtUtils jwtUtils;

    @Override
    public void run(String... args) throws Exception {

        String token = jwtUtils.generateToken(UUID.randomUUID(), TokenType.ACCESS_TOKEN, false);
        log.info("ACCESS TOKEN = {}", token);

        jwtUtils.revokeToken(token, TokenType.ACCESS_TOKEN);

        log.info("Is Revoked Token: {}", jwtUtils.isRevokedToken(token, TokenType.ACCESS_TOKEN));

        log.info("Is Token Valid: {}", jwtUtils.verifyToken(token, TokenType.ACCESS_TOKEN, false));

        log.info(jwtUtils.extractJwtUsefulClaims(token, TokenType.ACCESS_TOKEN, false));

    }

}
