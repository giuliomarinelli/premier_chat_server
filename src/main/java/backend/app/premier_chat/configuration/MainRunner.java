package backend.app.premier_chat.configuration;

import backend.app.premier_chat.Models.enums.EncodeType;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

//@Component
@Log4j2
public class MainRunner implements CommandLineRunner {

    @Autowired
    private ConfigurationUtils configurationUtils;

    @Override
    public void run(String... args) throws Exception {
        for (int i = 0; i < 6; i++) log.info(
                "Secret n. {}: {}", i + 1, configurationUtils.keyGenerator(32, EncodeType.BASE_64
                )); // 32 byte ==> 256 bit
    }

}
