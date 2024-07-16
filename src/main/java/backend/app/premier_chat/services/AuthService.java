package backend.app.premier_chat.services;

import backend.app.premier_chat.Models.Dto.inputDto.UserPostInputDto;
import backend.app.premier_chat.Models.Dto.outputDto.ConfirmOutputDto;
import backend.app.premier_chat.Models.Dto.outputDto.ConfirmRegistrationOutputDto;
import backend.app.premier_chat.Models.configuration.AuthorizationStrategyConfiguration;
import backend.app.premier_chat.Models.configuration.JwtUsefulClaims;
import backend.app.premier_chat.Models.configuration.TokenPair;
import backend.app.premier_chat.Models.configuration.jwt_configuration.ActivationTokenConfiguration;
import backend.app.premier_chat.Models.entities.User;
import backend.app.premier_chat.Models.enums.EncodeType;
import backend.app.premier_chat.Models.enums.TokenPairType;
import backend.app.premier_chat.Models.enums.TokenType;
import backend.app.premier_chat.exception_handling.BadRequestException;
import backend.app.premier_chat.exception_handling.InternalServerErrorException;
import backend.app.premier_chat.exception_handling.NotFoundException;
import backend.app.premier_chat.exception_handling.UnauthorizedException;
import backend.app.premier_chat.repositories.jpa.UserRepository;
import backend.app.premier_chat.security.JwtUtils;
import backend.app.premier_chat.security.SecurityUtils;
import io.jsonwebtoken.ExpiredJwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

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

    public Mono<ConfirmRegistrationOutputDto> register(UserPostInputDto userPostInputDto) throws BadRequestException, InternalServerErrorException {

        return Mono.fromCallable(() -> {

            String totpSecret = "";

            try {
                User user = new User(
                        userPostInputDto.username(),
                        userPostInputDto.email(),
                        encoder.encode(userPostInputDto.password()),
                        totpSecret,
                        activationTokenConfiguration.getExpiresIn()
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
