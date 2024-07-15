package backend.app.premier_chat.repositories.jpa;

import backend.app.premier_chat.Models.entities.RevokedToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface RevokedTokenRepository extends JpaRepository<RevokedToken, Integer> {

    public Optional<RevokedToken> findByJti(UUID jti);

    public Optional<RevokedToken> findByToken(String token);

}
