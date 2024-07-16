package backend.app.premier_chat.configuration;

import backend.app.premier_chat.Models.enums.EncodeType;
import backend.app.premier_chat.security.SecurityUtils;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

//@Component
@Order(2)
@Log4j2
public class MainRunner implements CommandLineRunner {

    @Autowired
    private SecurityUtils securityUtils;

    @Override
    public void run(String... args) throws Exception {
        for (int i = 0; i < 6; i++)
            log.info(
                    "Secret n. {}: {}", i + 1, securityUtils.keyGenerator(32, EncodeType.BASE_64
                    )); // 32 byte ==> 256 bit
    }

}
