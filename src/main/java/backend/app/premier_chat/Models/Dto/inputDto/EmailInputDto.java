package backend.app.premier_chat.Models.Dto.inputDto;

import jakarta.validation.constraints.NotBlank;

public record EmailInputDto(

        @NotBlank(message = "'email' field is required") // aggiungere pattern
        String email

) {}
