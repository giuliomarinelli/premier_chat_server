package backend.app.premier_chat.Models.Dto.outputDto;

import backend.app.premier_chat.Models.configuration.TokenPair;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;

@Data
@NoArgsConstructor
public class ConfirmWithJotpMetadataDto extends ConfirmOutputDto {

    private long TotpGeneratedAt;
    private long TotpExpiresAt;

    public ConfirmWithJotpMetadataDto(String message, HttpStatus httpStatus, JotpMetadataDto metadata) {
        super(message, httpStatus);
        TotpGeneratedAt = metadata.getTotpGeneratedAt();
        TotpExpiresAt = metadata.getTotpExpiresAt();
    }
}
