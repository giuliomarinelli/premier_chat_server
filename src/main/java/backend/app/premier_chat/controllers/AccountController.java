package backend.app.premier_chat.controllers;

import backend.app.premier_chat.Models.Dto.outputDto.ConfirmOutputDto;
import backend.app.premier_chat.Models.Dto.outputDto.ConfirmWithJotpMetadataDto;
import backend.app.premier_chat.Models.Dto.outputDto.ConfirmWithJotpMetadataWithObscuredPhoneNumberDto;
import backend.app.premier_chat.Models.configuration.AuthorizationStrategyConfiguration;
import backend.app.premier_chat.Models.configuration.JotpConfiguration;
import backend.app.premier_chat.Models.configuration.SecurityCookieConfiguration;
import backend.app.premier_chat.Models.configuration.TokenPair;
import backend.app.premier_chat.Models.configuration.jwt_configuration.PhoneNumberVerificationTokenConfiguration;
import backend.app.premier_chat.Models.enums.AuthorizationStrategy;
import backend.app.premier_chat.Models.enums.TokenPairType;
import backend.app.premier_chat.Models.enums.TokenType;
import backend.app.premier_chat.Models.enums._2FAStrategy;
import backend.app.premier_chat.exception_handling.BadRequestException;
import backend.app.premier_chat.exception_handling.ForbiddenException;
import backend.app.premier_chat.exception_handling.NotFoundException;
import backend.app.premier_chat.repositories.jpa.UserRepository;
import backend.app.premier_chat.security.JwtUtils;
import backend.app.premier_chat.security.SecurityUtils;
import backend.app.premier_chat.services.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.UUID;

@RestController
@RequestMapping("/api/account")
public class AccountController {

    public AccountController(
            AuthService authService,
            AuthorizationStrategyConfiguration authorizationStrategyConfiguration,
            SecurityCookieConfiguration securityCookieConfiguration,
            JwtUtils jwtUtils,
            UserRepository userRepository,
            SecurityUtils securityUtils,
            JotpConfiguration jotpConfiguration,
            PhoneNumberVerificationTokenConfiguration phoneNumberVerificationTokenConfiguration
    ) {
        this.authService = authService;
        this.authorizationStrategyConfiguration = authorizationStrategyConfiguration;
        this.securityCookieConfiguration = securityCookieConfiguration;
        this.jwtUtils = jwtUtils;
        this.userRepository = userRepository;
        this.securityUtils = securityUtils;
        this.jotpConfiguration = jotpConfiguration;
        this.phoneNumberVerificationTokenConfiguration = phoneNumberVerificationTokenConfiguration;
    }

    private final AuthService authService;

    private final AuthorizationStrategyConfiguration authorizationStrategyConfiguration;

    private final SecurityCookieConfiguration securityCookieConfiguration;

    private final JwtUtils jwtUtils;

    private final UserRepository userRepository;

    private final SecurityUtils securityUtils;

    private final JotpConfiguration jotpConfiguration;

    private final PhoneNumberVerificationTokenConfiguration phoneNumberVerificationTokenConfiguration;

    @PatchMapping("/2-factors-authentication/totp/sms/enable/request")
    public Mono<ResponseEntity<ConfirmWithJotpMetadataWithObscuredPhoneNumberDto>> requestTotpForSms2FaActivation(ServerHttpRequest req, ServerHttpResponse res) {

        String accessToken = jwtUtils.extractHttpTokensFromContext(req, AuthorizationStrategy.COOKIE).getAccessToken();

        UUID userId = jwtUtils.extractJwtUsefulClaims(accessToken, TokenType.ACCESS_TOKEN, true).getSub();

        return authService.generateTotpToVerifyPhoneNumberForSms2FaActivation(userId).map(metadata -> {
            String phoneNumber = userRepository.findPhoneNumberByUserId(userId).orElseThrow(
                    () -> new ForbiddenException("You don't have the permissions to access this resource")
            );
            ConfirmWithJotpMetadataWithObscuredPhoneNumberDto body = new ConfirmWithJotpMetadataWithObscuredPhoneNumberDto(
                    "An SMS was sent to your number with a verification " + jotpConfiguration.getDigits()
                            + " digits code.",
                    HttpStatus.OK,
                    metadata,
                    securityUtils.obscurePhoneNumber(phoneNumber)
            );

            String phoneNumberVerificationToken = jwtUtils.generateToken(
                    userId,
                    TokenType.PHONE_NUMBER_VERIFICATION_TOKEN,
                    false);

            res.addCookie(ResponseCookie.from("__phone_number_verification_token", phoneNumberVerificationToken)
                    .domain(securityCookieConfiguration.getDomain())
                    .httpOnly(securityCookieConfiguration.isHttpOnly())
                    .path(securityCookieConfiguration.getPath())
                    .sameSite(securityCookieConfiguration.getSameSite())
                    .secure(securityCookieConfiguration.isSecure())
                    .maxAge(phoneNumberVerificationTokenConfiguration.getExpiresIn() / 1000)
                    .build());

            return ResponseEntity.status(HttpStatus.OK).body(body);
        });

    }

    @PatchMapping("/2-factors-authentication/totp/{strategy}/disable")
    public Mono<ResponseEntity<ConfirmOutputDto>> disableSms2Fa(@PathVariable String strategy, ServerHttpRequest req) {

        _2FAStrategy _strategy;

        try {
            _strategy = _2FAStrategy.valueOf(strategy.replaceAll("-", "_").toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new BadRequestException("Malformed 2 factors authentication strategy field");
        }

        String accessToken = jwtUtils.extractHttpTokensFromContext(req, AuthorizationStrategy.COOKIE).getAccessToken();

        UUID userId = jwtUtils.extractJwtUsefulClaims(accessToken, TokenType.ACCESS_TOKEN, true).getSub();

        return authService.disable2Fa(userId, _strategy)
                .map(ResponseEntity::ok);

    }

}
