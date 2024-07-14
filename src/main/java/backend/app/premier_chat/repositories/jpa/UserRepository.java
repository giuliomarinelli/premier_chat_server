package backend.app.premier_chat.repositories.jpa;

import backend.app.premier_chat.Models.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    @Query("SELECT u FROM User u WHERE u.id = :id AND (u.enabled = true OR u.mustActivateInto > :now)")
    public Optional<User> findValidUserByIdAndNow(UUID id, long now);

    public default Optional<User> findValidUserById(UUID id) {
        return findValidUserByIdAndNow(id, System.currentTimeMillis());
    }

    @Query("SELECT u FROM User u WHERE u.id = :id AND u.enabled = false AND u.mustActivateInto > :now")
    public Optional<User> findValidNotEnabledUserByIdAndNow(UUID id, long now);

    public default Optional<User> findValidNotEnabledUserById(UUID id) {
        return findValidNotEnabledUserByIdAndNow(id, System.currentTimeMillis());
    }

    public Optional<User> findByUsername(UUID username);

    public Optional<User> findByEmail(UUID email);

}
