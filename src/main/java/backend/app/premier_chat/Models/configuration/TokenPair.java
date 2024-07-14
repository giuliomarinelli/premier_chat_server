package backend.app.premier_chat.Models.configuration;

import backend.app.premier_chat.Models.enums.TokenPairType;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class TokenPair {

    String accessToken;
    String refreshToken;
    TokenPairType type;

}
