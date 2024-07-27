package backend.app.premier_chat.socketIo;

import backend.app.premier_chat.repositories.jpa.UserRepository;
import backend.app.premier_chat.socketIo.services.ClientService;
import backend.app.premier_chat.socketIo.services.SessionService;
import com.corundumstudio.socketio.SocketIOClient;
import org.springframework.http.HttpCookie;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Component
public class SocketUtils {

    private final SessionService sessionService;

    public SocketUtils(SessionService sessionService) {
        this.sessionService = sessionService;
    }

    public Map<String, HttpCookie> parseCookies(String cookieHeader) {
        Map<String, HttpCookie> cookies = new HashMap<>();
        if (cookieHeader == null || cookieHeader.isBlank()) return cookies;
        String[] rawCookies = cookieHeader.split(";");
        for (String rawCookie : rawCookies) {
            String key = rawCookie.trim().split("=")[0].trim();
            String value = rawCookie.trim().split("=")[1].trim();
            cookies.put(key, new HttpCookie(key, value));
        }
        return cookies;
    }

    public Optional<UUID> findUserIdFromClient(SocketIOClient client) {

        return sessionService.getUserIdFromSessionId(client.getSessionId());

    }

}
