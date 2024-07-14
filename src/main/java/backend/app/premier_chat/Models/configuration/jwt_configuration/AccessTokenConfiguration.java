package backend.app.premier_chat.Models.configuration.jwt_configuration;

public class AccessTokenConfiguration extends JwtConfiguration {

    public AccessTokenConfiguration(String secret, Long expiresIn) {
        super(secret, expiresIn);
    }

}
