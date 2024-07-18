package backend.app.premier_chat.Models.Dto.inputDto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class PhoneNumberVerificationDto extends AbstractVerificationBody {

        @NotBlank(message = "'phoneNumber' field is required")
        private String phoneNumber;

}
