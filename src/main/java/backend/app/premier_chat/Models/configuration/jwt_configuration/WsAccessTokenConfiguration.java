package backend.app.premier_chat.Models.configuration.jwt_configuration;

public class WsAccessTokenConfiguration extends JwtConfiguration {

    public WsAccessTokenConfiguration(String secret, Long expiresIn) {
        super(secret, expiresIn);
    }

}
