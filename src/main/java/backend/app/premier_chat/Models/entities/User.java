package backend.app.premier_chat.Models.entities;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

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

    private boolean enabled;

    public User(String username, String hashedPassword) {
        this.username = username;
        this.hashedPassword = hashedPassword;
        createdAt = System.currentTimeMillis();
        enabled = false;
    }

    @Transient
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
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
