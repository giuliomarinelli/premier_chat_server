package backend.app.premier_chat.Models.Dto.outputDto;

import backend.app.premier_chat.Models.configuration.TokenPair;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;

@Data
@NoArgsConstructor
public class ConfirmOtputHeaderLoginDto extends ConfirmOutputDto {

    public ConfirmOtputHeaderLoginDto(String message, HttpStatus httpStatus, TokenPair httpTokenPair, TokenPair wsTokenPair) {
        super(message, httpStatus);
        this.httpTokenPair = httpTokenPair;
        this.wsTokenPair = wsTokenPair;
    }

    private TokenPair httpTokenPair;
    private TokenPair wsTokenPair;

}
