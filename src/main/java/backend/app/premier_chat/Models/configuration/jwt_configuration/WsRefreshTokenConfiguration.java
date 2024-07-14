package backend.app.premier_chat.Models.configuration.jwt_configuration;

public class WsRefreshTokenConfiguration extends JwtConfiguration {

    public WsRefreshTokenConfiguration(String secret, Long expiresIn) {
        super(secret, expiresIn);
    }

}
