package backend.app.premier_chat.Models.Dto.outputDto;

import lombok.Data;
import org.springframework.http.HttpStatus;

@Data
public class ConfirmWithJotpMetadataWithObscuredPhoneNumberDto extends ConfirmWithJotpMetadataDto {

    private String obscuredPhoneNumber;

    public ConfirmWithJotpMetadataWithObscuredPhoneNumberDto(String message, HttpStatus httpStatus, JotpMetadataDto metadata, String obscuredPhoneNumber) {
        super(message, httpStatus, metadata);
        this.obscuredPhoneNumber = obscuredPhoneNumber;
    }
}
