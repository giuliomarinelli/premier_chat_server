package backend.app.premier_chat.Models.Dto.outputDto;

import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;

@Data
public class ConfirmRegistrationOutputDto extends ConfirmOutputDto {

    private String obscuredEmail;

    public ConfirmRegistrationOutputDto(String message, HttpStatus httpStatus, String obscuredEmail) {
        super(message, httpStatus);
        this.obscuredEmail = obscuredEmail;
    }


}
