package backend.app.premier_chat.Models.Dto.outputDto;

import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;

@Data
@NoArgsConstructor
public class ConfirmOutputCookieLoginWith2FaObscuredEmailDto extends ConfirmOutputDto {

    private String obscuredEmail;

    public ConfirmOutputCookieLoginWith2FaObscuredEmailDto(String message, HttpStatus httpStatus, String obscuredEmail) {
        super(message, httpStatus);
        this.obscuredEmail = obscuredEmail;
    }
}
