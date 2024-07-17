package backend.app.premier_chat.Models.Dto.outputDto;

import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;

@Data
@NoArgsConstructor
public class ConfirmOutputHeaderLoginWith2FaObscuredEmailAndPhoneNumberDto extends ConfirmOutputHeaderLoginWith2FaDto {

    private String obscuredEmail;
    private String obscuredPhoneNumber;

    public ConfirmOutputHeaderLoginWith2FaObscuredEmailAndPhoneNumberDto(String message, HttpStatus httpStatus, String preAuthorizationToken, String obscuredEmail, String obscuredPhoneNumber) {
        super(message, httpStatus, preAuthorizationToken);
        this.obscuredEmail = obscuredEmail;
        this.obscuredPhoneNumber = obscuredPhoneNumber;
    }
}
