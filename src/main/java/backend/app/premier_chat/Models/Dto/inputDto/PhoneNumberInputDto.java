package backend.app.premier_chat.Models.Dto.inputDto;

import jakarta.validation.constraints.NotBlank;

public record PhoneNumberInputDto(

        @NotBlank(message = "'phoneNumber' field is required") // aggiungere pattern
        String phoneNumber

) {}
