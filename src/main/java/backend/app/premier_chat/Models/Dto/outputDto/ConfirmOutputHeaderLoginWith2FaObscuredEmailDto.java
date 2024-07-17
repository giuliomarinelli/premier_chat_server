package backend.app.premier_chat.Models.Dto.outputDto;

import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;

@Data
@NoArgsConstructor
public class ConfirmOutputHeaderLoginWith2FaObscuredEmailDto extends ConfirmOutputHeaderLoginWith2FaDto {

    private String obscuredEmail;

    public ConfirmOutputHeaderLoginWith2FaObscuredEmailDto(String message, HttpStatus httpStatus, String preAuthorizationToken, String obscuredEmail) {
        super(message, httpStatus, preAuthorizationToken);
        this.obscuredEmail = obscuredEmail;
    }
}
