package backend.app.premier_chat.Models.Dto.outputDto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@NoArgsConstructor
public class JotpWrapperOutputDTO extends TotpWrapperOutputDto {

    private long generatedAt;
    private long expiresAt;

    public JotpWrapperOutputDTO(String TOTP, long generatedAt, long expiresAt) {
        super(TOTP);
        this.generatedAt = generatedAt;
        this.expiresAt = expiresAt;
    }
}
