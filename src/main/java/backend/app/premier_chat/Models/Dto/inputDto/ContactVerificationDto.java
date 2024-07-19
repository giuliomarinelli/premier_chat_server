package backend.app.premier_chat.Models.Dto.inputDto;

import jakarta.validation.constraints.NotNull;

public record ContactVerificationDto(

        @NotNull(message = "'contact' field is required")
        String contact

) {}
