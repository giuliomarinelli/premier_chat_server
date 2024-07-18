package backend.app.premier_chat.Models.Dto.inputDto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record TotpInputDto(

        @NotBlank(message = "'totp' field is required")
        @Pattern(regexp = "^\\d{6}$", message = "Malformed 'totp' field. It must be a 6 digits numeric code")
        String totp

) {}
