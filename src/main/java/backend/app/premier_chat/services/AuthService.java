package backend.app.premier_chat.services;

import backend.app.premier_chat.Models.Dto.inputDto.UserPostInputDto;
import backend.app.premier_chat.Models.Dto.outputDto.ConfirmOutputDto;
import backend.app.premier_chat.Models.Dto.outputDto.ConfirmRegistrationOutputDto;
import backend.app.premier_chat.Models.configuration.JwtUsefulClaims;
import backend.app.premier_chat.Models.configuration.jwt_configuration.ActivationTokenConfiguration;
import backend.app.premier_chat.Models.entities.User;
import backend.app.premier_chat.Models.enums.EncodeType;
import backend.app.premier_chat.Models.enums.TokenType;
import backend.app.premier_chat.configuration.ConfigurationUtils;
import backend.app.premier_chat.exception_handling.BadRequestException;
import backend.app.premier_chat.exception_handling.InternalServerErrorException;
import backend.app.premier_chat.exception_handling.NotFoundException;
import backend.app.premier_chat.exception_handling.UnauthorizedException;
import backend.app.premier_chat.repositories.jpa.UserRepository;
import backend.app.premier_chat.security.JwtUtils;
import backend.app.premier_chat.security.SecurityUtils;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

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
    private ConfigurationUtils configurationUtils;

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private NotificationService notificationService;

    public Mono<ConfirmRegistrationOutputDto> register(UserPostInputDto userPostInputDto) throws BadRequestException, InternalServerErrorException {

        return Mono.fromCallable(() -> {

            String totpSecret = configurationUtils.keyGenerator(64, EncodeType.BASE_32);

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
                        "Welcome " + user.getUsername() + ".\\nThis is your activation token:\\n" + activationToken
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

    public ConfirmOutputDto activateUser(String activationToken) throws BadRequestException, NotFoundException {

        try {
            JwtUsefulClaims claims = jwtUtils.extractJwtUsefulClaims(activationToken, TokenType.ACTIVATION_TOKEN, false);
            User user = userRepository.findValidUserById(claims.getSub()).orElseThrow(
                    () -> new NotFoundException("User not found")
            );
            user.setEnabled(true);
            user.setUpdatedAt(System.currentTimeMillis());
            userRepository.save(user);
            return new ConfirmOutputDto("Account activated successfully", HttpStatus.OK);
        } catch (ExpiredJwtException e) {
            throw new BadRequestException("Time for account activation is over, please register again");
        } catch (UnauthorizedException e) {
            throw new NotFoundException("User not found");
        }

    }

}
