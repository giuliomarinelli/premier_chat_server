package backend.app.premier_chat.Models.Dto.outputDto;

import lombok.Data;
import org.springframework.http.HttpStatus;

@Data
public class ConfirmWithJotpMetadataWithObscuredEmailDto extends ConfirmWithJotpMetadataDto {

    private String obscuredEmail;

    public ConfirmWithJotpMetadataWithObscuredEmailDto(String message, HttpStatus httpStatus, JotpMetadataDto metadata, String obscuredEmail) {
        super(message, httpStatus, metadata);
        this.obscuredEmail = obscuredEmail;
    }
}
