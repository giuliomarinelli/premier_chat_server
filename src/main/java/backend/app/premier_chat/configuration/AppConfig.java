package backend.app.premier_chat.configuration;

import backend.app.premier_chat.Models.configuration.AuthorizationStrategyConfiguration;
import backend.app.premier_chat.Models.configuration.SecurityCookieConfiguration;
import backend.app.premier_chat.Models.configuration.jwt_configuration.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.SecureRandom;
import java.util.Properties;

@Configuration
public class AppConfig {

    @Bean
    public PasswordEncoder passwordEncoder() {
        return Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
    }

    @Bean
    public AccessTokenConfiguration accessTokenConfiguration(
            @Value("${spring.configuration.jwt.secrets.accessToken}") String secret,
            @Value("${spring.configuration.jwt.expiration.accessToken}") String expiration
    ) {
        return new AccessTokenConfiguration(secret, Long.parseLong(expiration));
    }

    @Bean
    public RefreshTokenConfiguration refreshTokenConfiguration(
            @Value("${spring.configuration.jwt.secrets.refreshToken}") String secret,
            @Value("${spring.configuration.jwt.expiration.refreshToken}") String expiration
    ) {
        return new RefreshTokenConfiguration(secret, Long.parseLong(expiration));
    }

    @Bean
    public WsAccessTokenConfiguration wsAccessTokenConfiguration(
            @Value("${spring.configuration.jwt.secrets.wsAccessToken}") String secret,
            @Value("${spring.configuration.jwt.expiration.wsAccessToken}") String expiration
    ) {
        return new WsAccessTokenConfiguration(secret, Long.parseLong(expiration));
    }

    @Bean
    public WsRefreshTokenConfiguration wsRefreshTokenConfiguration(
            @Value("${spring.configuration.jwt.secrets.wsRefreshToken}") String secret,
            @Value("${spring.configuration.jwt.expiration.wsRefreshToken}") String expiration
    ) {
        return new WsRefreshTokenConfiguration(secret, Long.parseLong(expiration));
    }

    @Bean
    public PreAuthorizationTokenConfiguration preAuthorizationTokenConfiguration(
            @Value("${spring.configuration.jwt.secrets.preAuthorizationToken}") String secret,
            @Value("${spring.configuration.jwt.expiration.preAuthorizationToken}") String expiration
    ) {
        return new PreAuthorizationTokenConfiguration(secret, Long.parseLong(expiration));
    }

    @Bean
    public ActivationTokenConfiguration activationTokenConfiguration(
            @Value("${spring.configuration.jwt.secrets.activationToken}") String secret,
            @Value("${spring.configuration.jwt.expiration.activationToken}") String expiration
    ) {
        return new ActivationTokenConfiguration(secret, Long.parseLong(expiration));
    }

    @Bean
    public AuthorizationStrategyConfiguration authorizationConfig(@Value("${spring.security.strategy}") String strategy) {
        return new AuthorizationStrategyConfiguration(strategy);
    }

    @Bean
    public JavaMailSenderImpl getMailSender(
            @Value("${spring.configuration.mail.smtp.host}") String smtpHost,
            @Value("${spring.configuration.mail.smtp.port}") String port,
            @Value("${spring.configuration.mail.username}") String username,
            @Value("${spring.configuration.mail.password}") String password,
            @Value("${spring.configuration.mail.transport.protocol}") String protocol,
            @Value("${spring.configuration.mail.smtp.auth}") String auth,
            @Value("${spring.configuration.mail.smtp.starttls.enable}") String starttls,
            @Value("${spring.configuration.mail.debug}") String debug,
            @Value("${spring.configuration.mail.ssl.enable}") String sslEnable
    ) {
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setHost(smtpHost);
        mailSender.setPort(Integer.parseInt(port));
        mailSender.setUsername(username);
        mailSender.setPassword(password);
        Properties props = mailSender.getJavaMailProperties();
        props.put("mail.transport.protocol", protocol);
        props.put("mail.smtp.auth", auth);
        props.put("mail.smtp.starttls.enable", starttls);
        props.put("mail.debug", debug);
        props.put("smtp.ssl.enable", sslEnable);
        return mailSender;
    }

    @Bean
    public SecurityCookieConfiguration securityCookieConfiguration(
            @Value("${spring.configuration.cookie.security.path}") String path,
            @Value("${spring.configuration.cookie.security.httpOnly}") boolean httpOnly,
            @Value("${spring.configuration.cookie.security.sameSite}") String sameSite,
            @Value("${spring.configuration.cookie.security.secure}") boolean secure,
            @Value("${spring.configuration.cookie.security.domain}") String domain,
            @Value("${spring.configuration.jwt.expiration.refreshToken}") long maxAgeMs
    ) {
        return new SecurityCookieConfiguration(path, httpOnly, sameSite, secure, domain, maxAgeMs);
    }

}
