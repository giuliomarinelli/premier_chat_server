package backend.app.premier_chat.security;

import backend.app.premier_chat.Models.configuration.JwtUsefulClaims;
import backend.app.premier_chat.Models.configuration.jwt_configuration.*;
import backend.app.premier_chat.Models.enums.TokenType;
import backend.app.premier_chat.exception_handling.UnauthorizedException;
import backend.app.premier_chat.repositories.jpa.RevokedTokenRepository;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.*;
import io.jsonwebtoken.security.SecurityException;
import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.UUID;

@Component
@Configuration
public class JwtUtils {

    @Autowired
    private AccessTokenConfiguration accessTokenConfiguration;

    @Autowired
    private RefreshTokenConfiguration refreshTokenConfiguration;

    @Autowired
    private WsAccessTokenConfiguration wsAccessTokenConfiguration;

    @Autowired
    private WsRefreshTokenConfiguration wsRefreshTokenConfiguration;

    @Autowired
    private PreAuthorizationTokenConfiguration preAuthorizationTokenConfiguration;

    @Autowired
    private ActivationTokenConfiguration activationTokenConfiguration;

    @Autowired
    private RevokedTokenRepository revokedTokenRepository;

    @Value("${spring.configuration.jwt.claims.iss}")
    private String jwtIssuer;

    private SecretKey generateSecretKey(String base64Secret) {
        byte[] keyBytes = Base64.decodeBase64(base64Secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    private JwtConfiguration getJwtConfigurationFromTokenType(TokenType type) throws UnauthorizedException {
        JwtConfiguration jwtConfiguration;
        switch (type) {
            case ACCESS_TOKEN -> jwtConfiguration = accessTokenConfiguration;
            case REFRESH_TOKEN -> jwtConfiguration = refreshTokenConfiguration;
            case WS_ACCESS_TOKEN -> jwtConfiguration = wsAccessTokenConfiguration;
            case WS_REFRESH_TOKEN -> jwtConfiguration = wsRefreshTokenConfiguration;
            case PRE_AUTHORIZATION_TOKEN -> jwtConfiguration = preAuthorizationTokenConfiguration;
            case ACTIVATION_TOKEN -> jwtConfiguration = activationTokenConfiguration;
            default -> throw new UnauthorizedException();
        }
        return jwtConfiguration;
    }

    public String generateToken(UUID userId, TokenType type, boolean restore) throws UnauthorizedException {

        JwtConfiguration jwtConfiguration = getJwtConfigurationFromTokenType(type);

        return Jwts.builder()
                .subject(userId.toString())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + jwtConfiguration.getExpiresIn()))
                .issuer(jwtIssuer)
                .claim("jti", UUID.randomUUID().toString())
                .claim("restore", restore)
                .signWith(generateSecretKey(jwtConfiguration.getSecret()), Jwts.SIG.HS256)
                .compact();

    }

    public boolean verifyTokenWithoutExceptions(String token, TokenType type) throws UnauthorizedException {

        JwtConfiguration jwtConfiguration = getJwtConfigurationFromTokenType(type);

        try {
            Jwts.parser().verifyWith(generateSecretKey(jwtConfiguration.getSecret())).build();
            return true;
        } catch (Exception e) {
            return false;
        }

    }

    public void verifyTokenWithExceptions(String token, TokenType type, boolean ignoreExpiration) throws UnauthorizedException {

        JwtConfiguration jwtConfiguration = getJwtConfigurationFromTokenType(type);

        try {
            Jwts.parser().verifyWith(generateSecretKey(jwtConfiguration.getSecret())).build();
        } catch (ExpiredJwtException e) {
            if (ignoreExpiration) throw e;
            throw new UnauthorizedException("Invalid access token");
        } catch (Exception e) {
            throw new UnauthorizedException("Invalid access token");
        }
    }

    public JwtUsefulClaims extractJwtUsefulClaims(String token, TokenType type, boolean ignoreExpiration) throws Exception {

        verifyTokenWithExceptions(token, type, ignoreExpiration);

        Object payload = Jwts.parser().build().parseSignedClaims(token).getPayload();
    }

}