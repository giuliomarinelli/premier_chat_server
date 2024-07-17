package backend.app.premier_chat.Models.Dto.outputDto;

import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;

@Data
@NoArgsConstructor
public class ConfirmOutputHeaderLoginWith2FaObscuredPhoneNumberDto extends ConfirmOutputHeaderLoginWith2FaDto {

    private String obscuredPhoneNumber;

    public ConfirmOutputHeaderLoginWith2FaObscuredPhoneNumberDto(String message, HttpStatus httpStatus, String preAuthorizationToken, String obscuredPhoneNumber) {
        super(message, httpStatus, preAuthorizationToken);
        this.obscuredPhoneNumber = obscuredPhoneNumber;
    }
}
