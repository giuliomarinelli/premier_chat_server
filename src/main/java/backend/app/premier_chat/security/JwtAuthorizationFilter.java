package backend.app.premier_chat.security;

import backend.app.premier_chat.Models.configuration.AuthorizationStrategyConfiguration;
import backend.app.premier_chat.Models.configuration.JwtUsefulClaims;
import backend.app.premier_chat.Models.configuration.SecurityCookieConfiguration;
import backend.app.premier_chat.Models.configuration.TokenPair;
import backend.app.premier_chat.Models.enums.AuthorizationStrategy;
import backend.app.premier_chat.Models.enums.TokenPairType;
import backend.app.premier_chat.Models.enums.TokenType;
import backend.app.premier_chat.exception_handling.UnauthorizedException;
import backend.app.premier_chat.repositories.jpa.UserRepository;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.util.annotation.NonNull;

import java.util.UUID;

public class JwtAuthorizationFilter implements WebFilter {

    @Autowired
    private AuthorizationStrategyConfiguration authorizationStrategyConfiguration;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private SecurityCookieConfiguration securityCookieConfiguration;

    @Autowired
    private UserRepository userRepository;

    @Override
    public @NonNull Mono<Void> filter(@NonNull ServerWebExchange exchange, @NonNull WebFilterChain chain) {

        ServerHttpRequest req = exchange.getRequest();

        AuthorizationStrategy strategy = authorizationStrategyConfiguration.getStrategy();

        switch (strategy) {

            case COOKIE -> {

                TokenPair tokenPair = jwtUtils.extractHttpTokensFromContext(req, strategy);

                if (!jwtUtils.verifyToken(tokenPair.getAccessToken(), TokenType.ACCESS_TOKEN, false)) {
                    // Verifico se il token è scaduto ma valido (Non valido se non ignoro la scadenza,
                    // e valido se ignoro la scadenza) => Significa che è scaduto
                    if (!jwtUtils.verifyToken(tokenPair.getAccessToken(), TokenType.ACCESS_TOKEN, true))
                        throw new UnauthorizedException("Invalid access token");

                    JwtUsefulClaims jwtUsefulClaims = jwtUtils.extractJwtUsefulClaims(tokenPair.getAccessToken(), TokenType.ACCESS_TOKEN, true);




                    if (userRepository.findValidEnabledUserById(userId).isEmpty())
                        throw new UnauthorizedException("Invalid access token");

                    TokenPair newTokenPair = jwtUtils.refreshTokenPair(tokenPair.getRefreshToken(), TokenPairType.HTTP);

                    ServerHttpResponse res = exchange.getResponse();


                    res.addCookie(ResponseCookie.from("__access_token", newTokenPair.getAccessToken())
                            .domain(securityCookieConfiguration.getDomain())
                            .httpOnly(securityCookieConfiguration.isHttpOnly())
                            .path(securityCookieConfiguration.getPath())
                            .sameSite(securityCookieConfiguration.getSameSite())
                            .build());

                }


            }
            case HEADER -> {
            }
            default -> throw new UnauthorizedException();

        }

    }

}
