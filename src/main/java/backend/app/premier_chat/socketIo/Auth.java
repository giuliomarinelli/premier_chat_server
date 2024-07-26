package backend.app.premier_chat.socketIo;

import backend.app.premier_chat.Models.enums.TokenType;
import backend.app.premier_chat.exception_handling.ForbiddenException;
import backend.app.premier_chat.exception_handling.UnauthorizedException;
import backend.app.premier_chat.security.JwtUtils;
import com.corundumstudio.socketio.AuthorizationListener;
import com.corundumstudio.socketio.AuthorizationResult;
import com.corundumstudio.socketio.HandshakeData;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Component;

@Component
@Log4j2
public class Auth implements AuthorizationListener {

    private final JwtUtils jwtUtils;

    public Auth(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    @Override
    public AuthorizationResult getAuthorizationResult(HandshakeData handshakeData) {


        String wsAccessToken;

        try {
            wsAccessToken = jwtUtils.extractWsTokensFromContextCookies(handshakeData).getAccessToken();
        } catch (ForbiddenException | UnauthorizedException e) {
            // messaggio di errore
            return AuthorizationResult.FAILED_AUTHORIZATION;
        }


        if (!jwtUtils.verifyToken(wsAccessToken, TokenType.WS_ACCESS_TOKEN, false)) {

            // Messaggio di errore...
            return AuthorizationResult.FAILED_AUTHORIZATION;

        }

        return AuthorizationResult.SUCCESSFUL_AUTHORIZATION;
    }
}