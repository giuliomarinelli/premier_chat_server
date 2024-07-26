package backend.app.premier_chat.security;

import backend.app.premier_chat.Models.configuration.AuthorizationStrategyConfiguration;
import backend.app.premier_chat.Models.configuration.JwtUsefulClaims;
import backend.app.premier_chat.Models.configuration.TokenPair;
import backend.app.premier_chat.Models.configuration.jwt_configuration.*;
import backend.app.premier_chat.Models.entities.RevokedToken;
import backend.app.premier_chat.Models.enums.AuthorizationStrategy;
import backend.app.premier_chat.Models.enums.TokenPairType;
import backend.app.premier_chat.Models.enums.TokenType;
import backend.app.premier_chat.exception_handling.ForbiddenException;
import backend.app.premier_chat.exception_handling.UnauthorizedException;
import backend.app.premier_chat.repositories.jpa.RevokedTokenRepository;
import backend.app.premier_chat.socketIo.SocketUtils;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.corundumstudio.socketio.HandshakeData;
import com.corundumstudio.socketio.SocketIOClient;
import lombok.ToString;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.codec.binary.Base64;
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


    private final AccessTokenConfiguration accessTokenConfiguration;

    private final RefreshTokenConfiguration refreshTokenConfiguration;

    private final WsAccessTokenConfiguration wsAccessTokenConfiguration;

    private final WsRefreshTokenConfiguration wsRefreshTokenConfiguration;

    private final PreAuthorizationTokenConfiguration preAuthorizationTokenConfiguration;

    private final ActivationTokenConfiguration activationTokenConfiguration;

    private final RevokedTokenRepository revokedTokenRepository;

    private final AuthorizationStrategyConfiguration authorizationStrategyConfiguration;

    private final PhoneNumberVerificationTokenConfiguration phoneNumberVerificationTokenConfiguration;

    private final EmailVerificationTokenConfiguration emailVerificationTokenConfiguration;

    private final String jwtIssuer;

    private final SocketUtils socketUtils;

    public JwtUtils(
            AccessTokenConfiguration accessTokenConfiguration,
            RefreshTokenConfiguration refreshTokenConfiguration,
            WsAccessTokenConfiguration wsAccessTokenConfiguration,
            WsRefreshTokenConfiguration wsRefreshTokenConfiguration,
            PreAuthorizationTokenConfiguration preAuthorizationTokenConfiguration,
            ActivationTokenConfiguration activationTokenConfiguration,
            RevokedTokenRepository revokedTokenRepository,
            AuthorizationStrategyConfiguration authorizationStrategyConfiguration,
            PhoneNumberVerificationTokenConfiguration phoneNumberVerificationTokenConfiguration,
            EmailVerificationTokenConfiguration emailVerificationTokenConfiguration,
            @Value("${spring.configuration.jwt.claims.iss}") String jwtIssuer,
            SocketUtils socketUtils
    ) {
        this.accessTokenConfiguration = accessTokenConfiguration;
        this.refreshTokenConfiguration = refreshTokenConfiguration;
        this.wsAccessTokenConfiguration = wsAccessTokenConfiguration;
        this.wsRefreshTokenConfiguration = wsRefreshTokenConfiguration;
        this.preAuthorizationTokenConfiguration = preAuthorizationTokenConfiguration;
        this.activationTokenConfiguration = activationTokenConfiguration;
        this.revokedTokenRepository = revokedTokenRepository;
        this.authorizationStrategyConfiguration = authorizationStrategyConfiguration;
        this.phoneNumberVerificationTokenConfiguration = phoneNumberVerificationTokenConfiguration;
        this.emailVerificationTokenConfiguration = emailVerificationTokenConfiguration;
        this.jwtIssuer = jwtIssuer;
        this.socketUtils = socketUtils;
    }

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
            case PHONE_NUMBER_VERIFICATION_TOKEN -> jwtConfiguration = phoneNumberVerificationTokenConfiguration;
            case EMAIL_VERIFICATION_TOKEN -> jwtConfiguration = emailVerificationTokenConfiguration;
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
            throw new UnauthorizedException("Revoked " + type.name().toLowerCase().replaceAll("_", " "));

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

    public TokenPair extractHttpTokensFromContext(ServerHttpRequest req, AuthorizationStrategy strategy) throws UnauthorizedException {

        switch (authorizationStrategyConfiguration.getStrategy()) {
            case COOKIE -> {
                if (req.getCookies().isEmpty())
                    throw new UnauthorizedException("No provided access token and refresh token");
                Map<String, HttpCookie> cookies = req.getCookies().toSingleValueMap();
                if (cookies.get("__access_token") == null || cookies.get("__access_token").getValue().isBlank())
                    throw new UnauthorizedException("No provided access token");
                if (cookies.get("__refresh_token") == null || cookies.get("__refresh_token").getValue().isBlank())
                    throw new UnauthorizedException("No provided refresh token");
                return new TokenPair(
                        cookies.get("__access_token").getValue(),
                        cookies.get("__refresh_token").getValue(),
                        TokenPairType.HTTP
                );
            }
            case HEADER -> {
                String autorizationHeader = req.getHeaders().getFirst("Authorization");
                if (autorizationHeader == null) throw new UnauthorizedException("No provided access token");
                if (!autorizationHeader.startsWith("Bearer "))
                    throw new UnauthorizedException("Malformed Authorization header");
                String accessToken = autorizationHeader.split(" ")[1];
                return new TokenPair(accessToken, null, TokenPairType.HTTP);
            }
            default -> throw new UnauthorizedException();
        }

    }

    public TokenPair extractWsTokensFromContextCookies(HandshakeData handshakeData) {

        Map<String, HttpCookie> cookies = socketUtils.parseCookies(handshakeData.getHttpHeaders().get("Cookie"));

        if (cookies.get("__ws_access_token") == null || cookies.get("__ws_access_token").getValue().isBlank())
            throw new ForbiddenException("You don't have the permissions to access this resource");

        if (cookies.get("__ws_refresh_token") == null || cookies.get("__ws_refresh_token").getValue().isBlank())
            throw new ForbiddenException("You don't have the permissions to access this resource");

        return new TokenPair(
                cookies.get("__ws_access_token").getValue(),
                cookies.get("__ws_refresh_token").getValue(),
                TokenPairType.WS
        );

    }

    public TokenPair extractWsTokensFromContextCookies(SocketIOClient client) {

        return extractWsTokensFromContextCookies(client.getHandshakeData());

    }

    public void revokeToken(String token, TokenType type) {
        try {
            UUID jti = extractJwtUsefulClaims(token, type, true).getJti();
            revokedTokenRepository.save(new RevokedToken(jti, token, type));
        } catch (JWTVerificationException e) {
            revokedTokenRepository.save(new RevokedToken(null, token, type));
        }

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
                log.info("Chiamo il metodo per refreshare i token http");
                JwtUsefulClaims payload = extractJwtUsefulClaims(refreshToken, TokenType.REFRESH_TOKEN, false);
                log.info("refresh effettuato, revoco il refresh token precedente");
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