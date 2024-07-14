package backend.app.premier_chat.Models.configuration;

import backend.app.premier_chat.Models.enums.TokenType;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.UUID;

@Data
@AllArgsConstructor
public class JwtUsefulClaims {

    private UUID sub;
    private UUID jti;
    private boolean restore;
    private TokenType typ;

}
