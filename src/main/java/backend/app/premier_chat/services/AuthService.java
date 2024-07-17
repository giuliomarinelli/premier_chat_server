package backend.app.premier_chat.services;

import backend.app.premier_chat.Models.Dto.inputDto.UserPostInputDto;
import backend.app.premier_chat.Models.Dto.outputDto.ConfirmOutputDto;
import backend.app.premier_chat.Models.Dto.outputDto.ConfirmRegistrationOutputDto;
import backend.app.premier_chat.Models.Dto.outputDto.JotpMetadataDto;
import backend.app.premier_chat.Models.Dto.outputDto.JotpWrapperOutputDTO;
import backend.app.premier_chat.Models.configuration.AuthorizationStrategyConfiguration;
import backend.app.premier_chat.Models.configuration.JotpConfiguration;
import backend.app.premier_chat.Models.configuration.JwtUsefulClaims;
import backend.app.premier_chat.Models.configuration.TokenPair;
import backend.app.premier_chat.Models.configuration.jwt_configuration.ActivationTokenConfiguration;
import backend.app.premier_chat.Models.entities.User;
import backend.app.premier_chat.Models.enums.EncodeType;
import backend.app.premier_chat.Models.enums.TokenPairType;
import backend.app.premier_chat.Models.enums.TokenType;
import backend.app.premier_chat.Models.enums._2FAStrategy;
import backend.app.premier_chat.exception_handling.*;
import backend.app.premier_chat.repositories.jpa.UserRepository;
import backend.app.premier_chat.security.JwtUtils;
import backend.app.premier_chat.security.SecurityUtils;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
public class AuthService {

    @Autowired
    private SecurityUtils securityUtils;

    @Autowired
    private PasswordEncoder encoder;

    @Autowired
    private ActivationTokenConfiguration activationTokenConfiguration;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private NotificationService notificationService;

    @Autowired
    private AuthorizationStrategyConfiguration authorizationStrategyConfiguration;

    @Autowired
    private JotpConfiguration jotpConfiguration;

    public Mono<ConfirmRegistrationOutputDto> register(UserPostInputDto userPostInputDto) throws BadRequestException, InternalServerErrorException {

        return Mono.fromCallable(() -> {

            String totpSecret = "";

            try {
                User user = new User(
                        userPostInputDto.username(),
                        userPostInputDto.email(),
                        encoder.encode(userPostInputDto.password()),
                        totpSecret,
                        activationTokenConfiguration.getExpiresIn(),
                        userPostInputDto.phoneNumber()
                );
                userRepository.save(user);
                String activationToken = jwtUtils.generateToken(user.getId(), TokenType.ACTIVATION_TOKEN, false);
                notificationService.sendEmail(
                        user.getEmail(),
                        "Registration to PremierChat",
                        "Welcome " + user.getUsername() + "\n\nThis is your activation token:\n\n" +
                                activationToken
                );
            } catch (DataIntegrityViolationException e) {
                if (userRepository.findValidUserByUsername(userPostInputDto.username()).isPresent())
                    throw new BadRequestException("Username already exist");
                if (userRepository.findValidUserByEmail(userPostInputDto.email()).isPresent())
                    throw new BadRequestException("Email already exist");
                throw new InternalServerErrorException("Data Integrity Error");
            }

            return new ConfirmRegistrationOutputDto(
                    "Registered successfully, an email with activation token was sent to user",
                    HttpStatus.OK,
                    securityUtils.obscureEmail(userPostInputDto.email())
            );
        });

    }

    public Mono<ConfirmOutputDto> activateUser(String activationToken) throws BadRequestException, NotFoundException {

        return Mono.fromCallable(() -> {
            try {
                JwtUsefulClaims claims = jwtUtils.extractJwtUsefulClaims(activationToken, TokenType.ACTIVATION_TOKEN, true);
                User user = userRepository.findValidUserById(claims.getSub()).orElseThrow(
                        () -> new NotFoundException("User not found")
                );
                user.setEnabled(true);
                user.setUpdatedAt(System.currentTimeMillis());
                userRepository.save(user);
                jwtUtils.revokeToken(activationToken, TokenType.ACTIVATION_TOKEN);
                return new ConfirmOutputDto("Account activated successfully", HttpStatus.OK);
            } catch (ExpiredJwtException e) {
                throw new BadRequestException("Time for account activation is over, please register again");
            } catch (UnauthorizedException e) {
                throw new NotFoundException("User not found");
            }
        });

    }

    public UUID usernameAndPasswordAuthentication(String username, String password) {

        User user = userRepository.findValidEnabledUserByUsername(username).orElseThrow(
                () -> new UnauthorizedException("Username and/or password are wrong")
        );

        if (!encoder.matches(password, user.getHashedPassword()))
            throw new UnauthorizedException("Username and/or password are wrong");

        // credenziali corrette

        return user.getId();

    }

    public boolean is2FaEnabled(UUID userId) {

        User user = userRepository.findValidEnabledUserById(userId).orElseThrow(
                () -> new UnauthorizedException("An authentication error occurred")
        );

        return !user.get_2FAStrategies().isEmpty();

    }

    public Mono<JotpMetadataDto> verifyContactBeforeGeneratingTOTP(String preAuthorizationToken, String contact, _2FAStrategy strategy) {

        return Mono.fromCallable(() -> {

            UUID userId;

            try {
                userId = jwtUtils.extractJwtUsefulClaims(preAuthorizationToken, TokenType.PRE_AUTHORIZATION_TOKEN, false)
                        .getSub();
            } catch (Exception e) {
                throw new ForbiddenException("You don't have the permissions to access this resource");
            }

            User user = userRepository.findValidEnabledUserById(userId).orElseThrow(
                    () -> new ForbiddenException("You don't have the permissions to access this resource")
            );

            if (!user.get_2FAStrategies().contains(strategy))
                throw new BadRequestException(strategy.name().toLowerCase() + " strategy for 2 factor authentication is not enabled for this user");

            // Codice per autennticazione a 2 fattori a 6 cifre, valido 60 secondi
            JotpWrapperOutputDTO wrapper;
            try {
                wrapper = securityUtils.generateJotpTOTP(user.getTotpSecret());
            } catch (IOException | NoSuchAlgorithmException | InvalidKeyException e) {
                throw new InternalServerErrorException("Error while generating 2 factor authentication code. " +
                        e.getMessage());
            }

            switch (strategy) {
                case EMAIL -> {
                    if (!contact.equals(user.getEmail())) {
                        jwtUtils.revokeToken(preAuthorizationToken, TokenType.PRE_AUTHORIZATION_TOKEN);
                        throw new UnauthorizedException("Email entered is wrong");
                    }
                    notificationService.sendEmail(
                            user.getEmail(),
                            "Your code to access Premier Chat", "Hello " + user.getUsername() + "\n\n" +
                                    "Here is your code to access Premier Chat: " + wrapper.getTOTP() + "\n\n" +
                                    "It's valid " + jotpConfiguration.getPeriod() + " seconds."

                    );
                }
                case SMS -> {
                    if (!contact.equals(user.getPhoneNumber())) {
                        jwtUtils.revokeToken(preAuthorizationToken, TokenType.PRE_AUTHORIZATION_TOKEN);
                        throw new UnauthorizedException("Phone Number entered is wrong");
                    }
                    notificationService.sendSms(
                            user.getPhoneNumber(), "Hello " + user.getUsername() +
                                    ". Here is your code to access Premier Chat: " + wrapper.getTOTP() + "\n\n" +
                                    "It's valid " + jotpConfiguration.getPeriod() + " seconds."
                    );
                }
                default -> throw new UnauthorizedException();
            }

            return new JotpMetadataDto(wrapper.getGeneratedAt(), wrapper.getExpiresAt());

        });


    }


    public Map<TokenPairType, TokenPair> performAuthentication(UUID userId, boolean restore) {

        Map<TokenPairType, TokenPair> tokensMap = new HashMap<>();

        tokensMap.put(
                TokenPairType.HTTP, new TokenPair(
                        jwtUtils.generateToken(userId, TokenType.ACCESS_TOKEN, restore),
                        jwtUtils.generateToken(userId, TokenType.REFRESH_TOKEN, restore),
                        TokenPairType.HTTP
                )
        );

        tokensMap.put(
                TokenPairType.WS, new TokenPair(
                        jwtUtils.generateToken(userId, TokenType.WS_ACCESS_TOKEN, restore),
                        jwtUtils.generateToken(userId, TokenType.WS_REFRESH_TOKEN, restore),
                        TokenPairType.HTTP
                )
        );

        return tokensMap;

    }


}
