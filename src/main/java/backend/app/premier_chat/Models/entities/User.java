package backend.app.premier_chat.Models.entities;

import backend.app.premier_chat.Models.enums.UserRole;
import backend.app.premier_chat.Models.enums._2FAStrategy;
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
                @Index(name = "user_locked_idx", columnList = "locked")
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

    @Column(unique = true)
    private String email;

    private boolean hasEmailBeenModified;

    @JsonIgnore
    private String hashedPassword;

    private long createdAt;

    private long updatedAt;

    private List<_2FAStrategy> _2FAStrategies = new ArrayList<>(); // Strategie di 2FA attive e disponibili all'uso

    private String phoneNumber;

    @JsonIgnore
    private String totpSecret;

    @JsonIgnore
    private long mustActivateInto;

    @JsonIgnore
    private boolean enabled;

    @JsonIgnore
    private boolean locked;

    private List<UserRole> roles = new ArrayList<>();

    public User(String username, String email, String hashedPassword, String totpSecret, long msForActivation, String phoneNumber) {
        this.username = username;
        this.hashedPassword = hashedPassword;
        this.email = email;
        this.totpSecret = totpSecret;
        this.phoneNumber = phoneNumber;
        createdAt = updatedAt = System.currentTimeMillis();
        mustActivateInto = createdAt + msForActivation;
        enabled = false;
        locked = false;
        roles.add(UserRole.USER);
        hasEmailBeenModified = false;
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
        return !locked;
    }

    @Transient
    @Override
    public boolean isEnabled() {
        return enabled;
    }
}
