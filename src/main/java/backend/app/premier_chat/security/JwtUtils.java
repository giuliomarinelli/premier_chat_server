package backend.app.premier_chat.security;

import backend.app.premier_chat.Models.configuration.AuthorizationStrategyConfiguration;
import backend.app.premier_chat.Models.configuration.JwtUsefulClaims;
import backend.app.premier_chat.Models.configuration.TokenPair;
import backend.app.premier_chat.Models.configuration.jwt_configuration.*;
import backend.app.premier_chat.Models.entities.RevokedToken;
import backend.app.premier_chat.Models.enums.TokenPairType;
import backend.app.premier_chat.Models.enums.TokenType;
import backend.app.premier_chat.exception_handling.UnauthorizedException;
import backend.app.premier_chat.repositories.jpa.RevokedTokenRepository;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.*;
import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.Map;
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

    @Autowired
    private AuthorizationStrategyConfiguration authorizationStrategyConfiguration;

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
                .claim("typ", type.name())
                .signWith(generateSecretKey(jwtConfiguration.getSecret()), Jwts.SIG.HS256)
                .compact();

    }

    public boolean verifyTokenWithoutExceptions(String token, TokenType type) throws UnauthorizedException {

        JwtConfiguration jwtConfiguration = getJwtConfigurationFromTokenType(type);

        try {
            Jwts.parser().verifyWith(generateSecretKey(jwtConfiguration.getSecret())).build();
            return !isRevokedToken(token);
        } catch (Exception e) {
            return false;
        }

    }

    public void verifyTokenWithExceptions(String token, TokenType type, boolean ignoreExpiration) throws UnauthorizedException {

        JwtConfiguration jwtConfiguration = getJwtConfigurationFromTokenType(type);

        try {
            Jwts.parser().verifyWith(generateSecretKey(jwtConfiguration.getSecret())).build();
            if (isRevokedToken(token)) throw new UnauthorizedException("Invalid JWT token");
        } catch (ExpiredJwtException e) {
            if (ignoreExpiration) throw e;
            throw new UnauthorizedException("Invalid JWT token");
        } catch (Exception e) {
            throw new UnauthorizedException("Invalid JWT token");
        }
    }

    public JwtUsefulClaims extractJwtUsefulClaims(String token, TokenType type, boolean ignoreExpiration) throws UnauthorizedException {

        verifyTokenWithExceptions(token, type, ignoreExpiration);

        Claims payload = Jwts.parser().build().parseSignedClaims(token).getPayload();

        return new JwtUsefulClaims(
                UUID.fromString(payload.getSubject()),
                UUID.fromString((String) payload.get("jti")),
                (boolean) payload.get("restore"),
                TokenType.valueOf((String) payload.get("typ")) //... IllegalArgumentException
        );

    }

    public JwtUsefulClaims extractJwtUsefulClaims(ServerHttpRequest req) throws UnauthorizedException {

        switch (authorizationStrategyConfiguration.getStrategy()) {
            case COOKIE -> {
                Map<String, HttpCookie> cookies = req.getCookies().toSingleValueMap();
                TokenPair tokenPair = new TokenPair(cookies.get("__access_token").getValue(),
                        cookies.get("__refresh_token").getValue(), TokenPairType.HTTP);
                JwtUsefulClaims jwtUsefulClaims;
                try {
                    jwtUsefulClaims = extractJwtUsefulClaims(tokenPair.getAccessToken(), TokenType.ACCESS_TOKEN, true);
                } catch (ExpiredJwtException e) {
                    jwtUsefulClaims = extractJwtUsefulClaims(tokenPair.getRefreshToken(), TokenType.REFRESH_TOKEN, false);
                }
                return jwtUsefulClaims;
            }
            case HEADER -> {
                String autorizationHeader = req.getHeaders().getFirst("Authorization");
                if (autorizationHeader == null) throw new UnauthorizedException("No provided access token");
                if (!autorizationHeader.startsWith("Bearer "))
                    throw new UnauthorizedException("Malformed Authorization header");
                String accessToken = autorizationHeader.split(" ")[1];
                JwtUsefulClaims jwtUsefulClaims;
                try {
                    jwtUsefulClaims = extractJwtUsefulClaims(accessToken, TokenType.ACCESS_TOKEN, true);
                } catch (ExpiredJwtException e) {
                    throw new UnauthorizedException("Expired access token: " + e.getMessage());
                }
                return jwtUsefulClaims;
            }
            default -> throw new UnauthorizedException();
        }

    }

    public void revokeToken(String token) {
        TokenType type;
        UUID jti;
        try {
            Claims payload = Jwts.parser().build().parseSignedClaims(token).getPayload();
            type = TokenType.valueOf((String) payload.get("typ"));
            jti = UUID.fromString((String) payload.get("jti"));
        } catch (IllegalArgumentException e) {
            type = null;
            jti = null;
        }

//        if (jti == null) throw new SomeException..()

        revokedTokenRepository.save(new RevokedToken(jti, token, type));

    }

    public boolean isRevokedToken(String token) {
        // Gestire IllegalArgumentException o assenza del claim
        UUID jti = UUID.fromString((String) Jwts.parser().build().parseSignedClaims(token).getPayload().get("jti"));
        return revokedTokenRepository.findByJti(jti).isPresent();
    }


    public TokenPair refreshTokenPair(String refreshToken, TokenPairType type) throws UnauthorizedException {
        switch (type) {
            case HTTP -> {
                JwtUsefulClaims payload = extractJwtUsefulClaims(refreshToken, TokenType.REFRESH_TOKEN, false);
                revokeToken(refreshToken);
                return new TokenPair(
                        generateToken(payload.getSub(), TokenType.ACCESS_TOKEN, payload.isRestore()),
                        generateToken(payload.getSub(), TokenType.REFRESH_TOKEN, payload.isRestore()),
                        type
                );
            }
            case WS -> {
                JwtUsefulClaims payload = extractJwtUsefulClaims(refreshToken, TokenType.WS_REFRESH_TOKEN, false);
                revokeToken(refreshToken);
                return new TokenPair(
                        generateToken(payload.getSub(), TokenType.WS_ACCESS_TOKEN, payload.isRestore()),
                        generateToken(payload.getSub(), TokenType.WS_REFRESH_TOKEN, payload.isRestore()),
                        type
                );
            }
            default -> throw new UnauthorizedException();
        }
    }

}