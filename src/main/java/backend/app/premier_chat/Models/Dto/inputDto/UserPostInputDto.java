package backend.app.premier_chat.Models.Dto.inputDto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

public record UserPostInputDto(

        @NotBlank(message = "'firstName' field is required")
        String firstName,

        @NotBlank(message = "'lastName' field is required")
        String lastName,

        @NotNull(message = "'dateOfBirth' field is required")
        Long dateOfBirth,

        @NotBlank(message = "'lastName' field is required")
        @Pattern(regexp = "^([A-Za-z]+)(_)?([A-Za-z])?$", message = "Malformed 'gender' field")
        String gender,

        @NotBlank(message = "'username' field is required")
        String username,

        @NotBlank(message = "'email' field is required")
        String email,

        @NotBlank(message = "'password' field is required")
        String password,

        @Pattern(regexp = "^(\\+\\d+)?$", message = "'phoneNumber' field is malformed")
        String phoneNumber
        // VALIDAZIONE DEI PATTERN
) {}
