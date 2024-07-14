package backend.app.premier_chat.Models.configuration;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.UUID;

@Data
@AllArgsConstructor
public class JwtUsefulClaims {

    private UUID sub;
    private UUID jti;
    private boolean restore;

}
