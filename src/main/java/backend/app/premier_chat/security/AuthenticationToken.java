package backend.app.premier_chat.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import java.util.Collection;

public class AuthenticationToken extends AbstractAuthenticationToken {

    public AuthenticationToken(Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        super.setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }

}
