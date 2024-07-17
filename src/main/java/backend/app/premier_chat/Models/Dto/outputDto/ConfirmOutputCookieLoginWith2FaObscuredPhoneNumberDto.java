package backend.app.premier_chat.Models.Dto.outputDto;

import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;

@Data
@NoArgsConstructor
public class ConfirmOutputCookieLoginWith2FaObscuredPhoneNumberDto extends ConfirmOutputDto {

    private String obscuredPhoneNumber;

    public ConfirmOutputCookieLoginWith2FaObscuredPhoneNumberDto(String message, HttpStatus httpStatus, String obscuredPhoneNumber) {
        super(message, httpStatus);
        this.obscuredPhoneNumber = obscuredPhoneNumber;
    }
}
