package backend.app.premier_chat.Models.Dto.outputDto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class JotpMetadataDto {

    private long TotpGeneratedAt;
    private long TotpExpiresAt;

}
