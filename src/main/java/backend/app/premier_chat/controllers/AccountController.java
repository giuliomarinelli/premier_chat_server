package backend.app.premier_chat.controllers;

import backend.app.premier_chat.Models.Dto.inputDto.TotpInputDto;
import backend.app.premier_chat.Models.Dto.outputDto.ConfirmOutputDto;
import backend.app.premier_chat.Models.Dto.outputDto.ConfirmWithJotpMetadataDto;
import backend.app.premier_chat.Models.Dto.outputDto.ConfirmWithJotpMetadataWithObscuredEmailDto;
import backend.app.premier_chat.Models.Dto.outputDto.ConfirmWithJotpMetadataWithObscuredPhoneNumberDto;
import backend.app.premier_chat.Models.configuration.AuthorizationStrategyConfiguration;
import backend.app.premier_chat.Models.configuration.JotpConfiguration;
import backend.app.premier_chat.Models.configuration.SecurityCookieConfiguration;
import backend.app.premier_chat.Models.configuration.TokenPair;
import backend.app.premier_chat.Models.configuration.jwt_configuration.EmailVerificationTokenConfiguration;
import backend.app.premier_chat.Models.configuration.jwt_configuration.PhoneNumberVerificationTokenConfiguration;
import backend.app.premier_chat.Models.entities.User;
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
import jakarta.validation.Valid;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

import java.util.Map;
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
            PhoneNumberVerificationTokenConfiguration phoneNumberVerificationTokenConfiguration,
            EmailVerificationTokenConfiguration emailVerificationTokenConfiguration
    ) {
        this.authService = authService;
        this.authorizationStrategyConfiguration = authorizationStrategyConfiguration;
        this.securityCookieConfiguration = securityCookieConfiguration;
        this.jwtUtils = jwtUtils;
        this.userRepository = userRepository;
        this.securityUtils = securityUtils;
        this.jotpConfiguration = jotpConfiguration;
        this.phoneNumberVerificationTokenConfiguration = phoneNumberVerificationTokenConfiguration;
        this.emailVerificationTokenConfiguration = emailVerificationTokenConfiguration;
        ;
    }

    private final AuthService authService;

    private final AuthorizationStrategyConfiguration authorizationStrategyConfiguration;

    private final SecurityCookieConfiguration securityCookieConfiguration;

    private final JwtUtils jwtUtils;

    private final UserRepository userRepository;

    private final SecurityUtils securityUtils;

    private final JotpConfiguration jotpConfiguration;

    private final PhoneNumberVerificationTokenConfiguration phoneNumberVerificationTokenConfiguration;

    private final EmailVerificationTokenConfiguration emailVerificationTokenConfiguration;

    @GetMapping("/contact-verification/{strategy}/request")
    public Mono<ResponseEntity<ConfirmOutputDto>> requestTotpForContactVerification(@PathVariable String strategy, ServerHttpRequest req, ServerHttpResponse res) {

        _2FAStrategy _strategy;

        try {
            _strategy = _2FAStrategy.valueOf(strategy.replaceAll("-", "_").toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new BadRequestException("Malformed verification strategy field");
        }

        String accessToken = jwtUtils.extractHttpTokensFromContext(req, AuthorizationStrategy.COOKIE).getAccessToken();

        UUID userId = jwtUtils.extractJwtUsefulClaims(accessToken, TokenType.ACCESS_TOKEN, true).getSub();

        User user = userRepository.findValidEnabledUserById(userId).orElseThrow(
                () -> new ForbiddenException("You don't have the permissions to access this resource")
        );

        switch (_strategy) {

            case SMS -> {

                if (!user.isPhoneNumberVerified())
                    throw new BadRequestException(
                            "Phone number hasn't been verified. Please verify it before activating " +
                                    "2 factors authentication with SMS"
                    );

                return authService.generateTotpToVerifyContact(userId, _strategy).map(metadata -> {
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
            case EMAIL -> {

                return authService.generateTotpToVerifyContact(userId, _strategy).map(metadata -> {
                    String email = userRepository.findEmailByUserId(userId).orElseThrow(
                            () -> new ForbiddenException("You don't have the permissions to access this resource")
                    );
                    ConfirmWithJotpMetadataWithObscuredEmailDto body = new ConfirmWithJotpMetadataWithObscuredEmailDto(
                            "An email was sent to your address with a verification " + jotpConfiguration.getDigits()
                                    + " digits code.",
                            HttpStatus.OK,
                            metadata,
                            securityUtils.obscureEmail(email)
                    );

                    String emailVerificationToken = jwtUtils.generateToken(
                            userId,
                            TokenType.EMAIL_VERIFICATION_TOKEN,
                            false);

                    res.addCookie(ResponseCookie.from("__email_verification_token", emailVerificationToken)
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
            default -> throw new ForbiddenException("You don't have the permissions to access this resource");
        }


    }

    @PostMapping("/contact-verification/{strategy}/verify-totp")
    public Mono<ResponseEntity<ConfirmOutputDto>> validateNewContact(@Valid @RequestBody Mono<TotpInputDto> bodyInputMono, @PathVariable String strategy, ServerHttpRequest req) {

        return bodyInputMono.flatMap(bodyInput -> {

            String totp = bodyInput.totp();

            _2FAStrategy _strategy;

            try {
                _strategy = _2FAStrategy.valueOf(strategy.replaceAll("-", "_").toUpperCase());
            } catch (IllegalArgumentException e) {
                throw new BadRequestException("Malformed verification strategy field");
            }

            Map<String, HttpCookie> cookies = req.getCookies().toSingleValueMap();

            switch (_strategy) {

                case SMS -> {

                    HttpCookie phoneNumberVerificationTokenCookie = cookies.get("__phone_number_verification_token");

                    if (phoneNumberVerificationTokenCookie == null)
                        throw new ForbiddenException("You don't have the permissions to access this resource");

                    String phoneNumberVerificationToken = phoneNumberVerificationTokenCookie.getValue();

                    if (phoneNumberVerificationToken.isBlank())
                        throw new ForbiddenException("You don't have the permissions to access this resource");

                    UUID userId = jwtUtils.extractJwtUsefulClaims(phoneNumberVerificationToken,
                            TokenType.PHONE_NUMBER_VERIFICATION_TOKEN,
                            false
                    ).getSub();

                    User user = userRepository.findValidEnabledUserById(userId).orElseThrow(
                            () -> new ForbiddenException("You don't have the permissions to access this resource")
                    );

                    if (!securityUtils.verifyJotpTOTP(user.getTotpSecret(), totp)) {
                        jwtUtils.revokeToken(phoneNumberVerificationToken, TokenType.PHONE_NUMBER_VERIFICATION_TOKEN);
                        throw new BadRequestException("Wrong verification code");
                    }

                    user.setPhoneNumberVerified(true);

                    userRepository.save(user);

                    return Mono.just(new ConfirmOutputDto("Phone number has been verified successfully", HttpStatus.OK));

                }

                case EMAIL -> {

                    HttpCookie emailVerificationTokenCookie = cookies.get("__email_verification_token");

                    if (emailVerificationTokenCookie == null)
                        throw new ForbiddenException("You don't have the permissions to access this resource");

                    String emailNumberVerificationToken = emailVerificationTokenCookie.getValue();

                    if (emailNumberVerificationToken.isBlank())
                        throw new ForbiddenException("You don't have the permissions to access this resource");

                    UUID userId = jwtUtils.extractJwtUsefulClaims(emailNumberVerificationToken,
                            TokenType.EMAIL_VERIFICATION_TOKEN,
                            false
                    ).getSub();

                    User user = userRepository.findValidEnabledUserById(userId).orElseThrow(
                            () -> new ForbiddenException("You don't have the permissions to access this resource")
                    );

                    if (!securityUtils.verifyJotpTOTP(user.getTotpSecret(), totp)) {
                        jwtUtils.revokeToken(emailNumberVerificationToken, TokenType.EMAIL_VERIFICATION_TOKEN);
                        throw new BadRequestException("Wrong verification code");
                    }

                    user.setEmailVerified(true);

                    userRepository.save(user);

                    return Mono.just(new ConfirmOutputDto("Email has been verified successfully", HttpStatus.OK));

                }

                default -> throw new ForbiddenException("You don't have the permissions to access this resource");

            }


        }).map(body -> ResponseEntity.status(HttpStatus.OK).body(body));

    }


    @PostMapping("/2-factors-authentication/totp/{strategy}/disable")
    public Mono<ResponseEntity<ConfirmOutputDto>> disableFa(@PathVariable String strategy, ServerHttpRequest req) {

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

    @PostMapping("/2-factors-authentication/totp/{strategy}/enable")
    public Mono<ResponseEntity<ConfirmOutputDto>> disableSms2Fa(@PathVariable String strategy, ServerHttpRequest req) {

        _2FAStrategy _strategy;

        try {
            _strategy = _2FAStrategy.valueOf(strategy.replaceAll("-", "_").toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new BadRequestException("Malformed 2 factors authentication strategy field");
        }

        String accessToken = jwtUtils.extractHttpTokensFromContext(req, AuthorizationStrategy.COOKIE).getAccessToken();

        UUID userId = jwtUtils.extractJwtUsefulClaims(accessToken, TokenType.ACCESS_TOKEN, true).getSub();

        return authService.enable2Fa(userId, _strategy)
                .map(ResponseEntity::ok);

    }

}
