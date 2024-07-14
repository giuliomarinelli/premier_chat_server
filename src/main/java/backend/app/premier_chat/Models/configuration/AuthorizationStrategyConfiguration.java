package backend.app.premier_chat.Models.configuration;

import backend.app.premier_chat.Models.enums.AuthorizationStrategy;
import lombok.Data;
import lombok.extern.log4j.Log4j2;

@Data
@Log4j2
public class AuthorizationStrategyConfiguration {

    private AuthorizationStrategy strategy;

    public AuthorizationStrategyConfiguration(String strategy) {
        try {
            this.strategy = AuthorizationStrategy.valueOf(strategy);
        } catch (IllegalArgumentException e) {
            this.strategy = AuthorizationStrategy.HEADER; // Valore di default se non specificato o in caso di mancato fit
        } finally {
            log.info("Authorization Strategy: {}", this.strategy);
        }
    }
}
