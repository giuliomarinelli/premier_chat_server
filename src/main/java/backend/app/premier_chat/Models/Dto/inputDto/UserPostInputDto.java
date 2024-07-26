package backend.app.premier_chat.Models.Dto.inputDto;

import jakarta.validation.constraints.NotBlank;

public record UserPostInputDto(

        @NotBlank(message = "'firstName' field is required")
        String firstName,

        @NotBlank(message = "'lastName' field is required")
        String lastName,

        @NotBlank(message = "'username' field is required")
        String username,

        @NotBlank(message = "'email' field is required")
        String email,

        @NotBlank(message = "'password' field is required")
        String password,

        @NotBlank(message = "'phoneNumber' field is required")
        String phoneNumber
        // VALIDAZIONE DEI PATTERN
) {
}
