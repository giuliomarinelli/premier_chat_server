package backend.app.premier_chat.socketIo.services;

import com.corundumstudio.socketio.SocketIOClient;
import lombok.Getter;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
@Getter
public class ClientService {

    private final Map<UUID, SocketIOClient> onLineClients = new ConcurrentHashMap<>();

    public void add(UUID sessionId, SocketIOClient client) {
        onLineClients.put(sessionId, client);
    }

    public SocketIOClient get(UUID sessionId) {
        return onLineClients.get(sessionId);
    }

    public void remove(UUID sessionId) {
        onLineClients.remove(sessionId);
    }

}
