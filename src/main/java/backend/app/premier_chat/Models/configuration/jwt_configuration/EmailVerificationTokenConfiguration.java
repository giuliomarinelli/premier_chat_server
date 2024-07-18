package backend.app.premier_chat.Models.configuration.jwt_configuration;

public class EmailVerificationTokenConfiguration extends JwtConfiguration {

    public EmailVerificationTokenConfiguration(String secret, Long expiresIn) {
        super(secret, expiresIn);
    }

}
