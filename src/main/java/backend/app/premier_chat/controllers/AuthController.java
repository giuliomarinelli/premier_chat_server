package backend.app.premier_chat.controllers;

import backend.app.premier_chat.Models.Dto.inputDto.UserPostInputDto;
import backend.app.premier_chat.Models.Dto.outputDto.ConfirmRegistrationOutputDto;
import backend.app.premier_chat.exception_handling.BadRequestException;
import backend.app.premier_chat.exception_handling.InternalServerErrorException;
import backend.app.premier_chat.exception_handling.Validation;
import backend.app.premier_chat.services.AuthService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;


@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @PostMapping("/account/register")
    public Mono<ResponseEntity<ConfirmRegistrationOutputDto>> register(@Valid @RequestBody Mono<UserPostInputDto> userInput) {
        return userInput.flatMap(ui -> authService.register(ui))
                .map(ResponseEntity::ok);
    }

}
