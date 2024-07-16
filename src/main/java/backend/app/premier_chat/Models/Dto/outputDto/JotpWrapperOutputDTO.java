package backend.app.premier_chat.Models.Dto.outputDto;

import lombok.AllArgsConstructor;
import lombok.Data;


@Data
@AllArgsConstructor
public class JotpWrapperOutputDTO {

    private String TOTP;
    private long generatedAt;
    private long expiresAt;

}
