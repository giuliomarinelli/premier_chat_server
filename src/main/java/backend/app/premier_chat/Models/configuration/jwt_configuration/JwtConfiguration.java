package backend.app.premier_chat.Models.configuration.jwt_configuration;

import lombok.Data;

@Data
public class JwtConfiguration {

    private String secret;
    private Long expiresIn;

    public JwtConfiguration(String secret, Long expiresIn) {
        this.secret = secret;
        this.expiresIn = expiresIn;
    }

}

