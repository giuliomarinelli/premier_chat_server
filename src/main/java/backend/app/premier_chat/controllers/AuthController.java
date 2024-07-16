package backend.app.premier_chat.controllers;

import backend.app.premier_chat.Models.Dto.inputDto.UserPostInputDto;
import backend.app.premier_chat.Models.Dto.outputDto.ConfirmOutputDto;
import backend.app.premier_chat.Models.Dto.outputDto.ConfirmRegistrationOutputDto;
import backend.app.premier_chat.services.AuthService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;


@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

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



}
