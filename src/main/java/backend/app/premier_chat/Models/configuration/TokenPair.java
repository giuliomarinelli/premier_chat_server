package backend.app.premier_chat.Models.configuration;

import backend.app.premier_chat.Models.enums.TokenPairType;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class TokenPair {

    String accessToken;
    String refreshToken;
    TokenPairType type;

}
