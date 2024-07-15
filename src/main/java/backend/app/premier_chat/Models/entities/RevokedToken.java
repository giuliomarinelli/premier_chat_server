package backend.app.premier_chat.Models.entities;

import backend.app.premier_chat.Models.enums.TokenType;
import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Entity
@Table(
        name = "revoked_tokens",
        indexes = {
                @Index(name = "idx_revoked_tokens_type", columnList = "type")
        }
)
@Data
@NoArgsConstructor
public class RevokedToken {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "revoked_tokens_id_gen")
    @SequenceGenerator(name = "revoked_tokens_id_gen", sequenceName = "revoked_tokens_id_gen", allocationSize = 1, initialValue = 1)
    private Long id;

    @Column(unique = true)
    private UUID jti;

    @Column(length = 10000, unique = true)
    private String token;

    @Enumerated(EnumType.STRING)
    private TokenType type;

    public RevokedToken(UUID jti, String token, TokenType type) {
        this.jti = jti;
        this.token = token;
        this.type = type;
    }
}
