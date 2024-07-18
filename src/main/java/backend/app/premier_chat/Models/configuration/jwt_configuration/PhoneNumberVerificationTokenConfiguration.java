package backend.app.premier_chat.Models.configuration.jwt_configuration;

public class PhoneNumberVerificationTokenConfiguration extends JwtConfiguration {

    public PhoneNumberVerificationTokenConfiguration(String secret, Long expiresIn) {
        super(secret, expiresIn);
    }

}
