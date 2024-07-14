package backend.app.premier_chat.configuration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

@Configuration
@Component
@Order(1)
public class TwilioRunner implements CommandLineRunner {

    @Value("${twilio.accountSid}")
    private String accountSid;
    @Value("${twilio.authToken}")
    private String authToken;



    @Override
    public void run(String... args) throws Exception {

        Twilio.init(accountSid, authToken);


    }

}
