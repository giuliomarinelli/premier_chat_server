package backend.app.premier_chat.security;

import org.springframework.stereotype.Component;

@Component
public class SecurityUtils {

    public String obscureEmail(String email) {

        int i = email.indexOf("@");
        // Gestire l'eccezione nel caso in cui i = -1
        String visible = email.substring(i - 2, i);
        return "*".repeat(i -1) + visible + email.substring(i);

    }


}
