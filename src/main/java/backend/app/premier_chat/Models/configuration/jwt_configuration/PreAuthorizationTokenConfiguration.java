package backend.app.premier_chat.Models.configuration.jwt_configuration;

public class PreAuthorizationTokenConfiguration extends JwtConfiguration {

    public PreAuthorizationTokenConfiguration(String secret, Long expiresIn) {
        super(secret, expiresIn);
    }

}
