package backend.app.premier_chat.Models.configuration;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class JotpConfiguration {

    private int bytesNumberForBase32Secret;
    private int digits;

}
