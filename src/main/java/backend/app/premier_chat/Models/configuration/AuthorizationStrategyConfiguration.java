package backend.app.premier_chat.Models.configuration;

import lombok.Data;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;

@Data
@Log4j2
public class AuthorizationStrategyConfiguration {

    private AuthorizationStrategy strategy;

    public AuthorizationStrategyConfiguration(String strategy) {
        try {
            this.strategy = AuthorizationStrategy.valueOf(strategy);
        } catch (IllegalArgumentException e) {
            this.strategy = AuthorizationStrategy.HEADER; // Valore di default se non specificato o in caso di errore
        } finally {
            log.info("Authorization Strategy: " + this.strategy);
        }
    }
}
