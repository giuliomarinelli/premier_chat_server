package backend.app.premier_chat.Models.configuration.jwt_configuration;

public class ActivationTokenConfiguration extends JwtConfiguration {

    public ActivationTokenConfiguration(String secret, Long expiresIn) {
        super(secret, expiresIn);
    }

}
