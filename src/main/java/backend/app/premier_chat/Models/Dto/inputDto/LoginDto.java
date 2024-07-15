package backend.app.premier_chat.Models.Dto.inputDto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record LoginDto(

        @NotBlank(message = "'username' field is required")
        String username,

        @NotBlank(message = "'password' field is required")
        String password,

        @NotNull(message = "'restore' field is required")
        Boolean restore

) {}
