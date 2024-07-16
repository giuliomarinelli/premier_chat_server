package backend.app.premier_chat.controllers;

import backend.app.premier_chat.Models.Dto.inputDto.LoginDto;
import backend.app.premier_chat.Models.Dto.inputDto.UserPostInputDto;
import backend.app.premier_chat.Models.Dto.outputDto.ConfirmOtputHeaderLoginDto;
import backend.app.premier_chat.Models.Dto.outputDto.ConfirmOutputDto;
import backend.app.premier_chat.Models.Dto.outputDto.ConfirmRegistrationOutputDto;
import backend.app.premier_chat.Models.configuration.AuthorizationStrategyConfiguration;
import backend.app.premier_chat.Models.configuration.SecurityCookieConfiguration;
import backend.app.premier_chat.Models.configuration.TokenPair;
import backend.app.premier_chat.Models.enums.TokenPairType;
import backend.app.premier_chat.Models.enums.TokenType;
import backend.app.premier_chat.exception_handling.UnauthorizedException;
import backend.app.premier_chat.security.JwtUtils;
import backend.app.premier_chat.services.AuthService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.Map;
import java.util.UUID;


@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private AuthorizationStrategyConfiguration authorizationStrategyConfiguration;

    @Autowired
    private SecurityCookieConfiguration securityCookieConfiguration;

    @Autowired
    private JwtUtils jwtUtils;

    @PostMapping("/account/register")
    public Mono<ResponseEntity<ConfirmRegistrationOutputDto>> register(@Valid @RequestBody Mono<UserPostInputDto> userInput) {
        return userInput.flatMap(ui -> authService.register(ui))
                .map(res -> ResponseEntity.status(HttpStatus.CREATED).body(res));
    }

    @GetMapping("/account/activate")
    public Mono<ResponseEntity<ConfirmOutputDto>> activateAccount(@RequestParam("at") String activationToken) {
        return authService.activateUser(activationToken)
                .map(ResponseEntity::ok);
    }

    @PostMapping("/login")
    public Mono<ResponseEntity<ConfirmOutputDto>> login(@Valid @RequestBody Mono<LoginDto> loginDtoMono, ServerHttpResponse res) {
        return loginDtoMono.flatMap(loginDto -> {

            // Verifico la validità delle credenziali e ottengo lo userId
            UUID userId = authService.usernameAndPasswordAuthentication(loginDto.username(), loginDto.password());
            // Verifico se è attiva l'autenticazione a 2 fattori
            boolean is2FaEnabled = authService.is2FaEnabled(userId);

            if (!is2FaEnabled) {
                Map<TokenPairType, TokenPair> tokens = authService.performAuthentication(userId, loginDto.restore());
                switch (authorizationStrategyConfiguration.getStrategy()) {
                    case HEADER -> {
                        return new ConfirmOtputHeaderLoginDto("Logged in successfully",
                                HttpStatus.OK,
                                tokens.get(TokenPairType.HTTP),
                                tokens.get(TokenPairType.WS)
                        ); // Bisogna gestire in qualche modo il restore, per adesso lo lascio non gestito
                    }
                    case COOKIE -> {
                        if (loginDto.restore()) {

                            res.addCookie(ResponseCookie.from("__access_token", tokens.get(TokenPairType.HTTP).getAccessToken())
                                    .domain(securityCookieConfiguration.getDomain())
                                    .httpOnly(securityCookieConfiguration.isHttpOnly())
                                    .path(securityCookieConfiguration.getPath())
                                    .sameSite(securityCookieConfiguration.getSameSite())
                                    .maxAge(securityCookieConfiguration.getMaxAge())
                                    .secure(securityCookieConfiguration.isSecure())
                                    .build());

                            res.addCookie(ResponseCookie.from("__refresh_token", tokens.get(TokenPairType.HTTP).getRefreshToken())
                                    .domain(securityCookieConfiguration.getDomain())
                                    .httpOnly(securityCookieConfiguration.isHttpOnly())
                                    .path(securityCookieConfiguration.getPath())
                                    .sameSite(securityCookieConfiguration.getSameSite())
                                    .maxAge(securityCookieConfiguration.getMaxAge())
                                    .secure(securityCookieConfiguration.isSecure())
                                    .build());

                            res.addCookie(ResponseCookie.from("__ws_access_token", tokens.get(TokenPairType.WS).getAccessToken())
                                    .domain(securityCookieConfiguration.getDomain())
                                    .httpOnly(securityCookieConfiguration.isHttpOnly())
                                    .path(securityCookieConfiguration.getPath())
                                    .sameSite(securityCookieConfiguration.getSameSite())
                                    .maxAge(securityCookieConfiguration.getMaxAge())
                                    .secure(securityCookieConfiguration.isSecure())
                                    .build());

                            res.addCookie(ResponseCookie.from("__ws_refresh_token", tokens.get(TokenPairType.WS).getRefreshToken())
                                    .domain(securityCookieConfiguration.getDomain())
                                    .httpOnly(securityCookieConfiguration.isHttpOnly())
                                    .path(securityCookieConfiguration.getPath())
                                    .sameSite(securityCookieConfiguration.getSameSite())
                                    .maxAge(securityCookieConfiguration.getMaxAge())
                                    .secure(securityCookieConfiguration.isSecure())
                                    .build());


                        } else {

                            res.addCookie(ResponseCookie.from("__access_token", tokens.get(TokenPairType.HTTP).getAccessToken())
                                    .domain(securityCookieConfiguration.getDomain())
                                    .httpOnly(securityCookieConfiguration.isHttpOnly())
                                    .path(securityCookieConfiguration.getPath())
                                    .sameSite(securityCookieConfiguration.getSameSite())
                                    .secure(securityCookieConfiguration.isSecure())
                                    .build());

                            res.addCookie(ResponseCookie.from("__refresh_token", tokens.get(TokenPairType.HTTP).getRefreshToken())
                                    .domain(securityCookieConfiguration.getDomain())
                                    .httpOnly(securityCookieConfiguration.isHttpOnly())
                                    .path(securityCookieConfiguration.getPath())
                                    .sameSite(securityCookieConfiguration.getSameSite())
                                    .secure(securityCookieConfiguration.isSecure())
                                    .build());

                            res.addCookie(ResponseCookie.from("__ws_access_token", tokens.get(TokenPairType.WS).getAccessToken())
                                    .domain(securityCookieConfiguration.getDomain())
                                    .httpOnly(securityCookieConfiguration.isHttpOnly())
                                    .path(securityCookieConfiguration.getPath())
                                    .sameSite(securityCookieConfiguration.getSameSite())
                                    .secure(securityCookieConfiguration.isSecure())
                                    .build());

                            res.addCookie(ResponseCookie.from("__ws_refresh_token", tokens.get(TokenPairType.WS).getRefreshToken())
                                    .domain(securityCookieConfiguration.getDomain())
                                    .httpOnly(securityCookieConfiguration.isHttpOnly())
                                    .path(securityCookieConfiguration.getPath())
                                    .sameSite(securityCookieConfiguration.getSameSite())
                                    .secure(securityCookieConfiguration.isSecure())
                                    .build());

                        }
                    }
                    default -> throw new UnauthorizedException();
                }
                return new ConfirmOutputDto("Logged in successfully", HttpStatus.OK);
            } else {

                String preAuthorizationToken = jwtUtils.generateToken(userId, TokenType.PRE_AUTHORIZATION_TOKEN, loginDto.restore());



        }

    })
}

}
