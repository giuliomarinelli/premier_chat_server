package backend.app.premier_chat.Models.Dto.outputDto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class TotpWrapperOutputDto {

    private String TOTP;

}
