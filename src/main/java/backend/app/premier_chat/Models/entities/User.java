package backend.app.premier_chat.Models.entities;

import backend.app.premier_chat.Models.enums.UserRole;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

@Entity
@Table(
        name = "users",
        indexes = {
                @Index(name = "user_created_at_idx", columnList = "createdAt"),
                @Index(name = "user_enabled_idx", columnList = "enabled"),
        }
)
@NoArgsConstructor
@Data
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Setter(AccessLevel.NONE)
    private UUID id;

    @Column(columnDefinition = "VARCHAR(30)", unique = true)
    private String username;

    private String hashedPassword;

    private long createdAt;

    @JsonIgnore
    private long mustActivateInto;

    @JsonIgnore
    private boolean enabled;

    private List<UserRole> roles = new ArrayList<>();

    public User(String username, String hashedPassword, long msForActivation) {
        this.username = username;
        this.hashedPassword = hashedPassword;
        createdAt = System.currentTimeMillis();
        mustActivateInto = createdAt + msForActivation;
        enabled = false;
        roles.add(UserRole.USER);
    }

    @Transient
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles.parallelStream().map(role -> new SimpleGrantedAuthority(role.name())).toList();
    }

    @Transient
    @Override
    @JsonIgnore
    public String getPassword() {
        return "";
    }

    @Transient
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Transient
    @Override
    public boolean isEnabled() {
        return enabled;
    }
}
