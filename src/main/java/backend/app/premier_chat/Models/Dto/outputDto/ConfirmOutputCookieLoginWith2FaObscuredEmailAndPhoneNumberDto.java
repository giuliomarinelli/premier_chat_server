package backend.app.premier_chat.Models.Dto.outputDto;

import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;

@Data
@NoArgsConstructor
public class ConfirmOutputCookieLoginWith2FaObscuredEmailAndPhoneNumberDto extends ConfirmOutputDto {

    private String obscuredEmail;
    private String obscuredPhoneNumber;

    public ConfirmOutputCookieLoginWith2FaObscuredEmailAndPhoneNumberDto(String message, HttpStatus httpStatus, String obscuredEmail, String obscuredPhoneNumber) {
        super(message, httpStatus);
        this.obscuredEmail = obscuredEmail;
        this.obscuredPhoneNumber = obscuredPhoneNumber;
    }
}
