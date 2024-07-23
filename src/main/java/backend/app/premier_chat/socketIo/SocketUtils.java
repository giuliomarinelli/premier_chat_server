package backend.app.premier_chat.socketIo;

import org.springframework.http.HttpCookie;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
public class SocketUtils {

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

}
