package backend.app.premier_chat.socketIo.services;

import lombok.Getter;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
@Getter
public class SessionService {

    private final Map<UUID, Set<UUID>> sessionManagerMap = new ConcurrentHashMap<>();

    public boolean isUserOnLine(UUID userId) {
        return sessionManagerMap.containsKey(userId);
    }

    public void add(UUID userId, UUID sessionId) {
        if (sessionManagerMap.containsKey(userId))
            sessionManagerMap.get(userId).add(sessionId);
        else {
            sessionManagerMap.put(userId, new HashSet<>());
            sessionManagerMap.get(userId).add(sessionId);
        }
    }

    public Optional<UUID> getUserIdFromSessionId(UUID sessionId) {

        for (UUID userId : sessionManagerMap.keySet()) {
            if (sessionManagerMap.get(userId).contains(sessionId)) return Optional.of(userId);
        }
        return Optional.empty();

    }

    public Set<UUID> getSessionIdsFromUserId(UUID userId) {

        return sessionManagerMap.get(userId) != null ? sessionManagerMap.get(userId) : new HashSet<>();

    }

    public void delete(UUID sessionId) {

        if (getUserIdFromSessionId(sessionId).isEmpty()) return;

        UUID userId = getUserIdFromSessionId(sessionId).get();

        sessionManagerMap.get(userId).remove(sessionId);
        if (sessionManagerMap.get(userId).isEmpty()) sessionManagerMap.remove(userId);

    }

}
