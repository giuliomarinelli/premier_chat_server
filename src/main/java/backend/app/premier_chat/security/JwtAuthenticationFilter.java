package backend.app.premier_chat.security;

import backend.app.premier_chat.Models.configuration.AuthorizationStrategyConfiguration;
import backend.app.premier_chat.Models.configuration.JwtUsefulClaims;
import backend.app.premier_chat.Models.configuration.SecurityCookieConfiguration;
import backend.app.premier_chat.Models.configuration.TokenPair;
import backend.app.premier_chat.Models.entities.User;
import backend.app.premier_chat.Models.enums.AuthorizationStrategy;
import backend.app.premier_chat.Models.enums.TokenPairType;
import backend.app.premier_chat.Models.enums.TokenType;
import backend.app.premier_chat.exception_handling.UnauthorizedException;
import backend.app.premier_chat.repositories.jpa.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.util.annotation.NonNull;

import java.util.List;
import java.util.UUID;

@Component
public class JwtAuthenticationFilter implements WebFilter {

    @Autowired
    private AuthorizationStrategyConfiguration authorizationStrategyConfiguration;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private SecurityCookieConfiguration securityCookieConfiguration;

    @Autowired
    private UserRepository userRepository;

    private final List<String> publicEndpoints = List.of();

    private final List<String> publicPathPrefixes = List.of("/api/auth");

    @Override
    public @NonNull Mono<Void> filter(@NonNull ServerWebExchange exchange, @NonNull WebFilterChain chain) {

        ServerHttpRequest req = exchange.getRequest();

        if (publicEndpoints.contains(req.getPath().toString())) return chain.filter(exchange);

        for (String prefix : publicPathPrefixes) {
            if (req.getPath().toString().startsWith(prefix)) return chain.filter(exchange);
        }

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

                    UUID userId = jwtUsefulClaims.getSub();
                    boolean restore = jwtUsefulClaims.isRestore();


                    if (userRepository.findValidEnabledUserById(userId).isEmpty())
                        throw new UnauthorizedException("Invalid access token");

                    TokenPair newTokenPair = jwtUtils.refreshTokenPair(tokenPair.getRefreshToken(), TokenPairType.HTTP);

                    ServerHttpResponse res = exchange.getResponse();

                    if (restore) {

                        res.addCookie(ResponseCookie.from("__access_token", newTokenPair.getAccessToken())
                                .domain(securityCookieConfiguration.getDomain())
                                .httpOnly(securityCookieConfiguration.isHttpOnly())
                                .path(securityCookieConfiguration.getPath())
                                .sameSite(securityCookieConfiguration.getSameSite())
                                .maxAge(securityCookieConfiguration.getMaxAge())
                                .secure(securityCookieConfiguration.isSecure())
                                .build());

                        res.addCookie(ResponseCookie.from("__refresh_token", newTokenPair.getRefreshToken())
                                .domain(securityCookieConfiguration.getDomain())
                                .httpOnly(securityCookieConfiguration.isHttpOnly())
                                .path(securityCookieConfiguration.getPath())
                                .sameSite(securityCookieConfiguration.getSameSite())
                                .maxAge(securityCookieConfiguration.getMaxAge())
                                .secure(securityCookieConfiguration.isSecure())
                                .build());


                    } else {

                        res.addCookie(ResponseCookie.from("__access_token", newTokenPair.getAccessToken())
                                .domain(securityCookieConfiguration.getDomain())
                                .httpOnly(securityCookieConfiguration.isHttpOnly())
                                .path(securityCookieConfiguration.getPath())
                                .sameSite(securityCookieConfiguration.getSameSite())
                                .secure(securityCookieConfiguration.isSecure())
                                .build());

                        res.addCookie(ResponseCookie.from("__refresh_token", newTokenPair.getRefreshToken())
                                .domain(securityCookieConfiguration.getDomain())
                                .httpOnly(securityCookieConfiguration.isHttpOnly())
                                .path(securityCookieConfiguration.getPath())
                                .sameSite(securityCookieConfiguration.getSameSite())
                                .secure(securityCookieConfiguration.isSecure())
                                .build());

                    }
                }

                String ctxAccessToken = jwtUtils.extractHttpTokensFromContext(req, strategy).getAccessToken();

                UUID userId = jwtUtils.extractJwtUsefulClaims(ctxAccessToken, TokenType.ACCESS_TOKEN, true).getSub();

                assert userRepository.findValidEnabledUserById(userId).isPresent();
                User user = userRepository.findValidEnabledUserById(userId).get();

                AuthenticationToken authenticationToken = new AuthenticationToken(user.getAuthorities());

                return chain.filter(exchange).contextWrite(ReactiveSecurityContextHolder.withAuthentication(authenticationToken));

            }

            case HEADER -> {

                String accessToken = jwtUtils.extractHttpTokensFromContext(req, strategy).getAccessToken();

                if (!jwtUtils.verifyToken(accessToken, TokenType.ACCESS_TOKEN, false))
                    throw new UnauthorizedException("Invalid or expired access token");

                UUID userId = jwtUtils.extractJwtUsefulClaims(accessToken, TokenType.ACCESS_TOKEN, true).getSub();

                assert userRepository.findValidEnabledUserById(userId).isPresent();
                User user = userRepository.findValidEnabledUserById(userId).get();

                AuthenticationToken authenticationToken = new AuthenticationToken(user.getAuthorities());

                return chain.filter(exchange).contextWrite(ReactiveSecurityContextHolder.withAuthentication(authenticationToken));


            }
            default -> throw new UnauthorizedException();

        }

    }

}
