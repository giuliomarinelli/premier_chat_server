package backend.app.premier_chat.Models.configuration.jwt_configuration;

public class RefreshTokenConfiguration extends JwtConfiguration {

    public RefreshTokenConfiguration(String secret, Long expiresIn) {
        super(secret, expiresIn);
    }

}
