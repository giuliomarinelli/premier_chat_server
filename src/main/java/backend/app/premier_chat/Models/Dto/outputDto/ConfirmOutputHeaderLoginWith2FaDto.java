package backend.app.premier_chat.Models.Dto.outputDto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;

@Data
@NoArgsConstructor
public class ConfirmOutputHeaderLoginWith2FaDto extends ConfirmOutputDto {

    private String preAuthorizationToken;

    public ConfirmOutputHeaderLoginWith2FaDto(String message, HttpStatus httpStatus, String preAuthorizationToken) {
        super(message, httpStatus);
        this.preAuthorizationToken = preAuthorizationToken;
    }
}
