package backend.app.premier_chat.socketIo;

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
        return AuthorizationResult.SUCCESSFUL_AUTHORIZATION;
    }
}