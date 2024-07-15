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
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

@Component
@Configuration
@Log4j2
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

    private byte[] generateSecretKeyBytes(String base64Secret) {
        return Base64.decodeBase64(base64Secret);
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

        log.info("generateToken => jwtConfiguration = {}", jwtConfiguration);

        Algorithm algorithm = Algorithm.HMAC256(generateSecretKeyBytes(jwtConfiguration.getSecret()));
        return JWT.create()
                .withIssuer(jwtIssuer)
                .withSubject(userId.toString())
                .withJWTId(UUID.randomUUID().toString())
                .withClaim("typ", type.name())
                .withClaim("restore", restore)
                .withIssuedAt(new Date(System.currentTimeMillis()))
                .withExpiresAt(new Date(System.currentTimeMillis() + jwtConfiguration.getExpiresIn()))
                .sign(algorithm);

    }

    public boolean verifyToken(String token, TokenType type, boolean ignoreExpiration) throws UnauthorizedException {

        JwtConfiguration jwtConfiguration = getJwtConfigurationFromTokenType(type);
        try {
            Algorithm algorithm = Algorithm.HMAC256(generateSecretKeyBytes(jwtConfiguration.getSecret()));
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(jwtIssuer)
                    .withClaim("typ", type.name())
                    .build();

            verifier.verify(token);
            return !isRevokedToken(token, type);
        } catch (JWTVerificationException e) {
            return e instanceof TokenExpiredException && ignoreExpiration;
        }

    }


    public JwtUsefulClaims extractJwtUsefulClaims(String token, TokenType type, boolean ignoreExpiration) throws UnauthorizedException {

        if (isRevokedToken(token, type))
            throw new UnauthorizedException("Invalid " + type.name().toLowerCase().replaceAll("_", " "));

        JwtConfiguration jwtConfiguration = getJwtConfigurationFromTokenType(type);

        try {
            Algorithm algorithm = Algorithm.HMAC256(generateSecretKeyBytes(jwtConfiguration.getSecret()));

            JWTVerifier verifier;

            if (ignoreExpiration) {

                verifier = JWT.require(algorithm)
                        .withIssuer(jwtIssuer)
                        .withClaim("typ", type.name())
                        .acceptExpiresAt(31556889864403199L)
                        .build();
            } else {

                verifier = JWT.require(algorithm)
                        .withIssuer(jwtIssuer)
                        .withClaim("typ", type.name())
                        .build();

            }

            DecodedJWT decodedJWT = verifier.verify(token);

            return new JwtUsefulClaims(
                    UUID.fromString(decodedJWT.getSubject()),
                    UUID.fromString(decodedJWT.getId()),
                    decodedJWT.getClaim("restore").asBoolean(),
                    TokenType.valueOf(decodedJWT.getClaim("typ").asString())
            ); //... IllegalArgumentException


        } catch (JWTVerificationException e) {
            throw new UnauthorizedException("Invalid " + type.name().toLowerCase().replaceAll("_", " "));
        }
    }

    public JwtUsefulClaims extractJwtUsefulClaims(ServerHttpRequest req) throws UnauthorizedException {

        switch (authorizationStrategyConfiguration.getStrategy()) {
            case COOKIE -> {
                Map<String, HttpCookie> cookies = req.getCookies().toSingleValueMap();
                TokenPair tokenPair = new TokenPair(cookies.get("__access_token").getValue(),
                        cookies.get("__refresh_token").getValue(), TokenPairType.HTTP);

                return extractJwtUsefulClaims(tokenPair.getAccessToken(), TokenType.ACCESS_TOKEN, true);

            }
            case HEADER -> {
                String autorizationHeader = req.getHeaders().getFirst("Authorization");
                if (autorizationHeader == null) throw new UnauthorizedException("No provided access token");
                if (!autorizationHeader.startsWith("Bearer "))
                    throw new UnauthorizedException("Malformed Authorization header");
                String accessToken = autorizationHeader.split(" ")[1];
                JwtUsefulClaims jwtUsefulClaims;
                return extractJwtUsefulClaims(accessToken, TokenType.ACCESS_TOKEN, false);
            }
            default -> throw new UnauthorizedException();
        }

    }

    public void revokeToken(String token, TokenType type) {

        UUID jti = extractJwtUsefulClaims(token, type, false).getJti();
        revokedTokenRepository.save(new RevokedToken(jti, token, type));

    }

    public boolean isRevokedToken(String token, TokenType type) {

        JwtConfiguration jwtConfiguration = getJwtConfigurationFromTokenType(type);

        Algorithm algorithm = Algorithm.HMAC256(generateSecretKeyBytes(jwtConfiguration.getSecret()));

        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer(jwtIssuer)
                .withClaim("typ", type.name())
                .acceptExpiresAt(31556889864403199L)
                .build();

        UUID jti = UUID.fromString(verifier.verify(token).getId());

        return revokedTokenRepository.findByJti(jti).isPresent();

    }

    public boolean isRevokedToken(String token) {

        return revokedTokenRepository.findByToken(token).isPresent();

    }


    public TokenPair refreshTokenPair(String refreshToken, TokenPairType type) throws UnauthorizedException {
        switch (type) {
            case HTTP -> {
                JwtUsefulClaims payload = extractJwtUsefulClaims(refreshToken, TokenType.REFRESH_TOKEN, false);
                revokeToken(refreshToken, TokenType.REFRESH_TOKEN);
                return new TokenPair(
                        generateToken(payload.getSub(), TokenType.ACCESS_TOKEN, payload.isRestore()),
                        generateToken(payload.getSub(), TokenType.REFRESH_TOKEN, payload.isRestore()),
                        type
                );
            }
            case WS -> {
                JwtUsefulClaims payload = extractJwtUsefulClaims(refreshToken, TokenType.WS_REFRESH_TOKEN, false);
                revokeToken(refreshToken, TokenType.WS_REFRESH_TOKEN);
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