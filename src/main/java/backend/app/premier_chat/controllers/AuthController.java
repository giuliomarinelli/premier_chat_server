package backend.app.premier_chat.controllers;

import backend.app.premier_chat.Models.Dto.inputDto.*;
import backend.app.premier_chat.Models.Dto.outputDto.*;
import backend.app.premier_chat.Models.configuration.AuthorizationStrategyConfiguration;
import backend.app.premier_chat.Models.configuration.JotpConfiguration;
import backend.app.premier_chat.Models.configuration.SecurityCookieConfiguration;
import backend.app.premier_chat.Models.configuration.TokenPair;
import backend.app.premier_chat.Models.enums.AuthorizationStrategy;
import backend.app.premier_chat.Models.enums.TokenPairType;
import backend.app.premier_chat.Models.enums.TokenType;
import backend.app.premier_chat.Models.enums._2FAStrategy;
import backend.app.premier_chat.exception_handling.BadRequestException;
import backend.app.premier_chat.exception_handling.ForbiddenException;
import backend.app.premier_chat.exception_handling.UnauthorizedException;
import backend.app.premier_chat.repositories.jpa.UserRepository;
import backend.app.premier_chat.security.JwtUtils;
import backend.app.premier_chat.security.SecurityUtils;
import backend.app.premier_chat.services.AuthService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.List;
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

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private SecurityUtils securityUtils;

    @Autowired
    private JotpConfiguration jotpConfiguration;

    @PostMapping("/account/register")
    public Mono<ResponseEntity<ConfirmRegistrationOutputDto>> register(@Valid @RequestBody Mono<UserPostInputDto> userInput) {
        return userInput.flatMap(ui -> authService.register(ui)).map(res -> ResponseEntity.status(HttpStatus.CREATED).body(res));
    }

    @GetMapping("/account/activate")
    public Mono<ResponseEntity<ConfirmOutputDto>> activateAccount(@RequestParam("at") String activationToken) {
        return authService.activateUser(activationToken).map(ResponseEntity::ok);
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
                        ConfirmOtputHeaderLoginDto body = new ConfirmOtputHeaderLoginDto("Logged in successfully", HttpStatus.OK, tokens.get(TokenPairType.HTTP), tokens.get(TokenPairType.WS));
                        return Mono.just(body); // Utilizza Mono.just per avvolgere il risultato
                    }
                    case COOKIE -> {
                        if (loginDto.restore()) {

                            res.addCookie(ResponseCookie.from("__access_token",
                                            tokens.get(TokenPairType.HTTP).getAccessToken())
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

                            res.addCookie(ResponseCookie.from("__ws_access_token", tokens.get(TokenPairType.WS)
                                            .getAccessToken())
                                    .domain(securityCookieConfiguration.getDomain())
                                    .httpOnly(securityCookieConfiguration.isHttpOnly())
                                    .path(securityCookieConfiguration.getPath())
                                    .sameSite(securityCookieConfiguration.getSameSite())
                                    .maxAge(securityCookieConfiguration.getMaxAge())
                                    .secure(securityCookieConfiguration.isSecure())
                                    .build());

                            res.addCookie(ResponseCookie.from("__ws_refresh_token", tokens.get(TokenPairType.WS)
                                            .getRefreshToken())
                                    .domain(securityCookieConfiguration.getDomain())
                                    .httpOnly(securityCookieConfiguration.isHttpOnly())
                                    .path(securityCookieConfiguration.getPath())
                                    .sameSite(securityCookieConfiguration.getSameSite())
                                    .maxAge(securityCookieConfiguration.getMaxAge())
                                    .secure(securityCookieConfiguration.isSecure())
                                    .build());

                        } else {

                            res.addCookie(ResponseCookie.from("__access_token", tokens.get(TokenPairType.HTTP)
                                            .getAccessToken())
                                    .domain(securityCookieConfiguration.getDomain())
                                    .httpOnly(securityCookieConfiguration.isHttpOnly())
                                    .path(securityCookieConfiguration.getPath())
                                    .sameSite(securityCookieConfiguration.getSameSite())
                                    .maxAge(securityCookieConfiguration.getMaxAge())
                                    .secure(securityCookieConfiguration.isSecure())
                                    .build());

                            res.addCookie(ResponseCookie.from("__refresh_token", tokens.get(TokenPairType.HTTP)
                                            .getRefreshToken())
                                    .domain(securityCookieConfiguration.getDomain())
                                    .httpOnly(securityCookieConfiguration.isHttpOnly())
                                    .path(securityCookieConfiguration.getPath())
                                    .sameSite(securityCookieConfiguration.getSameSite())
                                    .maxAge(securityCookieConfiguration.getMaxAge())
                                    .secure(securityCookieConfiguration.isSecure())
                                    .build());

                            res.addCookie(ResponseCookie.from("__ws_access_token",
                                            tokens.get(TokenPairType.WS).getAccessToken())
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

                        }
                        ConfirmOutputDto body = new ConfirmOutputDto("Logged in successfully", HttpStatus.OK);
                        return Mono.just(body); // Utilizza Mono.just per avvolgere il risultato
                    }
                    default -> throw new UnauthorizedException();
                }
            } else {

                String preAuthorizationToken = jwtUtils.generateToken(userId, TokenType.PRE_AUTHORIZATION_TOKEN, loginDto.restore());

                List<_2FAStrategy> _2faStrategies = userRepository.find2FaStrategiesByUserId(userId).orElseThrow(() -> new UnauthorizedException("An authentication error occurred"));

                boolean _email = false, _sms = false;

                if (_2faStrategies.contains(_2FAStrategy.EMAIL)) _email = true;
                if (_2faStrategies.contains(_2FAStrategy.SMS)) _sms = true;

                switch (authorizationStrategyConfiguration.getStrategy()) {
                    case HEADER -> {
                        if (_email && !_sms) {
                            String email = userRepository.findEmailByUserId(userId).orElseThrow(
                                    () -> new UnauthorizedException("An authentication error occurred")
                            );
                            ConfirmOutputHeaderLoginWith2FaObscuredEmailDto body = new ConfirmOutputHeaderLoginWith2FaObscuredEmailDto(
                                    "First step of authentication went on successfully, please verify your email "
                                            + "to receive an authentication code to your email address",
                                    HttpStatus.OK,
                                    preAuthorizationToken,
                                    securityUtils.obscureEmail(email));

                            return Mono.just(body); // Utilizza Mono.just per avvolgere il risultato

                        } else if (!_email && _sms) {

                            String phoneNumber = userRepository.findPhoneNumberByUserId(userId).orElseThrow(
                                    () -> new UnauthorizedException("An authentication error occurred")
                            );
                            ConfirmOutputHeaderLoginWith2FaObscuredPhoneNumberDto body = new ConfirmOutputHeaderLoginWith2FaObscuredPhoneNumberDto(
                                    "First step of authentication went on successfully, please verify your phoneNumber "
                                            + "to receive an authentication code via SMS",
                                    HttpStatus.OK,
                                    preAuthorizationToken,
                                    securityUtils.obscurePhoneNumber(phoneNumber)
                            );

                            return Mono.just(body); // Utilizza Mono.just per avvolgere il risultato

                        } else {
                            String email = userRepository.findEmailByUserId(userId).orElseThrow(
                                    () -> new UnauthorizedException("An authentication error occurred")
                            );
                            String phoneNumber = userRepository.findPhoneNumberByUserId(userId).orElseThrow(
                                    () -> new UnauthorizedException("An authentication error occurred")
                            );
                            ConfirmOutputHeaderLoginWith2FaObscuredEmailAndPhoneNumberDto body = new ConfirmOutputHeaderLoginWith2FaObscuredEmailAndPhoneNumberDto(
                                    "First step of authentication went on successfully, please verify your email or your phoneNumber "
                                            + "to receive an authentication code via email or via SMS",
                                    HttpStatus.OK, preAuthorizationToken, securityUtils.obscureEmail(email),
                                    securityUtils.obscurePhoneNumber(phoneNumber));

                            return Mono.just(body); // Utilizza Mono.just per avvolgere il risultato
                        }
                    }
                    case COOKIE -> {

                        res.addCookie(ResponseCookie.from("__pre_authorization_token", preAuthorizationToken)
                                .domain(securityCookieConfiguration.getDomain())
                                .httpOnly(securityCookieConfiguration.isHttpOnly())
                                .path(securityCookieConfiguration.getPath())
                                .sameSite(securityCookieConfiguration.getSameSite())
                                .secure(securityCookieConfiguration.isSecure())
                                .build());

                        if (_email && !_sms) {

                            String email = userRepository.findEmailByUserId(userId).orElseThrow(
                                    () -> new UnauthorizedException("An authentication error occurred")
                            );
                            ConfirmOutputCookieLoginWith2FaObscuredEmailDto body = new ConfirmOutputCookieLoginWith2FaObscuredEmailDto(
                                    "First step of authentication went on successfully, please verify your email "
                                            + "to receive an authentication code to your email address",
                                    HttpStatus.OK,
                                    securityUtils.obscureEmail(email));

                            return Mono.just(body); // Utilizza Mono.just per avvolgere il risultato

                        } else if (!_email && _sms) {

                            String phoneNumber = userRepository.findPhoneNumberByUserId(userId).orElseThrow(
                                    () -> new UnauthorizedException("An authentication error occurred"));
                            ConfirmOutputCookieLoginWith2FaObscuredPhoneNumberDto body = new ConfirmOutputCookieLoginWith2FaObscuredPhoneNumberDto(
                                    "First step of authentication went on successfully, please verify your phoneNumber "
                                            + "to receive an authentication code via SMS",
                                    HttpStatus.OK,
                                    securityUtils.obscurePhoneNumber(phoneNumber));

                            return Mono.just(body); // Utilizza Mono.just per avvolgere il risultato

                        } else {

                            String email = userRepository.findEmailByUserId(userId).orElseThrow(
                                    () -> new UnauthorizedException("An authentication error occurred")
                            );
                            String phoneNumber = userRepository.findPhoneNumberByUserId(userId).orElseThrow(
                                    () -> new UnauthorizedException("An authentication error occurred")
                            );
                            ConfirmOutputCookieLoginWith2FaObscuredEmailAndPhoneNumberDto body = new ConfirmOutputCookieLoginWith2FaObscuredEmailAndPhoneNumberDto(
                                    "First step of authentication went on successfully, please verify your email or your phoneNumber "
                                            + "to receive an authentication code via email or via SMS",
                                    HttpStatus.OK,
                                    securityUtils.obscureEmail(email),
                                    securityUtils.obscurePhoneNumber(phoneNumber));
                            return Mono.just(body); // Utilizza Mono.just per avvolgere il risultato
                        }
                    }
                    default -> throw new UnauthorizedException();
                }

            }

        }).map(body -> ResponseEntity.status(HttpStatus.OK).body(body));
    }

    @GetMapping("/logout")
    public Mono<ResponseEntity<ConfirmOutputDto>> logout(ServerHttpRequest req, ServerHttpResponse res) {


        if (authorizationStrategyConfiguration.getStrategy().equals(AuthorizationStrategy.COOKIE)) {

            Map<String, HttpCookie> cookies = req.getCookies().toSingleValueMap();

            String accessToken = "";
            String refreshToken = "";
            String wsAccessToken = "";
            String wsRefreshToken = "";
            if (cookies.get("__ws_refresh_token") != null) accessToken = cookies.get("__access_token").getValue();
            if (cookies.get("__access_token") != null) refreshToken = cookies.get("__refresh_token").getValue();
            if (cookies.get("__refresh_token") != null) wsAccessToken = cookies.get("__ws_access_token").getValue();
            if (cookies.get("__ws_access_token") != null) wsRefreshToken = cookies.get("__ws_refresh_token").getValue();


            if (!accessToken.isEmpty())
                jwtUtils.revokeToken(accessToken, TokenType.ACCESS_TOKEN);

            if (!refreshToken.isEmpty())
                jwtUtils.revokeToken(refreshToken, TokenType.REFRESH_TOKEN);

            if (!wsAccessToken.isEmpty())

                jwtUtils.revokeToken(wsAccessToken, TokenType.WS_ACCESS_TOKEN);
            if (!wsRefreshToken.isEmpty())
                jwtUtils.revokeToken(wsRefreshToken, TokenType.WS_REFRESH_TOKEN);


            res.addCookie(ResponseCookie.from("__access_token", "")
                    .path(securityCookieConfiguration.getPath()).maxAge(0)
                    .build());

            res.addCookie(ResponseCookie.from("__refresh_token", "")
                    .path(securityCookieConfiguration.getPath()).maxAge(0)
                    .build());

            res.addCookie(ResponseCookie.from("__ws_access_token", "")
                    .path(securityCookieConfiguration.getPath()).maxAge(0)
                    .build());

            res.addCookie(ResponseCookie.from("__ws_refresh_token", "")
                    .path(securityCookieConfiguration.getPath()).maxAge(0)
                    .build());

        } else if (authorizationStrategyConfiguration.getStrategy().equals(AuthorizationStrategy.HEADER)) {

            String authorizationHeader = req.getHeaders().getFirst("Authorization");
            // .........revoca access token
            // Da rivedere questa parte. Va trovato un modo per revocare i token, si potrebbe creare una cache
            // di sessione, in ogni caso l'approccio tramite header resta più complesso perché è completamente STATELESS

        }
        ConfirmOutputDto body = new ConfirmOutputDto("Logged out successfully", HttpStatus.OK);
        return Mono.just(ResponseEntity.status(HttpStatus.OK).body(body));
    }

    @PostMapping("/2-factors-authentication/totp/request")
    public Mono<ResponseEntity<ConfirmWithJotpMetadataDto>> requestTotpFor2Fa(@Valid @RequestBody Mono<AbstractVerificationBody> bodyMono, ServerHttpRequest req) {

        // Per ora tralascio la strategia HEADER su cui tornerò in un secondo momento

        return bodyMono.flatMap(bodyInput -> {

            Map<String, HttpCookie> cookies = req.getCookies().toSingleValueMap();

            if (cookies.get("__pre_authorization_token") == null)
                throw new ForbiddenException("You don't have the permissions to access this resource");

            HttpCookie preAuthCookie = cookies.get("__pre_authorization_token");

            if (preAuthCookie.getValue().isBlank())
                throw new ForbiddenException("You don't have the permissions to access this resource");

            String preAuthorizationToken = preAuthCookie.getValue();

            UUID userId = jwtUtils.extractJwtUsefulClaims(
                    preAuthorizationToken,
                    TokenType.PRE_AUTHORIZATION_TOKEN,
                    false
            ).getSub();

            _2FAStrategy strategy = null;
            String contact = "";
            String message = "";

            if (bodyInput instanceof EmailVerificationDto) {
                strategy = _2FAStrategy.EMAIL;
                contact = ((EmailVerificationDto) bodyInput).getEmail();
                message = "A " + jotpConfiguration.getDigits() + " digits code valid " + jotpConfiguration.getPeriod() + " " +
                        "seconds has been sent to your email address";
            }
            else if (bodyInput instanceof PhoneNumberVerificationDto) {
                strategy = _2FAStrategy.SMS;
                contact = ((PhoneNumberVerificationDto) bodyInput).getPhoneNumber();
                message = "A " + jotpConfiguration.getDigits() + " digits code valid " + jotpConfiguration.getPeriod() + " " +
                        "seconds has been sent via SMS to your phone number";
            }
            if (strategy == null || contact.isEmpty() || message.isBlank())
                throw new BadRequestException();
            final String _message = message;

            return authService.verifyContactBeforeGeneratingTOTP(preAuthorizationToken, contact, strategy)
                    .map(jotpMetadataDto -> {

                        ConfirmWithJotpMetadataDto body = new ConfirmWithJotpMetadataDto(_message, HttpStatus.OK, jotpMetadataDto);
                        return ResponseEntity.status(HttpStatus.OK).body(body);

                    });



        });

    }


}

