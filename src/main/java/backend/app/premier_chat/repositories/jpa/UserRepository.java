package backend.app.premier_chat.repositories.jpa;

import backend.app.premier_chat.Models.entities.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    // Trova per id

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

    @Query("SELECT u FROM User u WHERE u.id = :id AND u.enabled = true")
    public Optional<User> findValidEnabledUserById(UUID id);

    // Trova per username

    @Query("SELECT u FROM User u WHERE u.username = :username AND (u.enabled = true OR u.mustActivateInto > :now)")
    public Optional<User> findValidUserByUsernameAndNow(String username, long now);

    public default Optional<User> findValidUserByUsernameAndNow(String username) {
        return findValidUserByUsernameAndNow(username, System.currentTimeMillis());
    }

    @Query("SELECT u FROM User u WHERE u.username = :username AND u.enabled = false AND u.mustActivateInto > :now")
    public Optional<User> findValidNotEnabledUserByUsernameAndNow(String username, long now);

    public default Optional<User> findValidNotEnabledUserByUsername(String username) {
        return findValidNotEnabledUserByUsernameAndNow(username, System.currentTimeMillis());
    }

    @Query("SELECT u FROM User u WHERE u.email = :email AND u.enabled = true")
    public Optional<User> findValidEnabledUserByUsername(String email);

    // Trova per email

    @Query("SELECT u FROM User u WHERE u.email = :email AND (u.enabled = true OR u.mustActivateInto > :now)")
    public Optional<User> findValidUserByEmailAndNow(String email, long now);

    public default Optional<User> findValidUserByEmailAndNow(String email) {
        return findValidUserByEmailAndNow(email, System.currentTimeMillis());
    }

    @Query("SELECT u FROM User u WHERE u.email = :email AND u.enabled = false AND u.mustActivateInto > :now")
    public Optional<User> findValidNotEnabledUserByEmailAndNow(String email, long now);

    public default Optional<User> findValidNotEnabledUserByEmail(String email) {
        return findValidNotEnabledUserByEmailAndNow(email, System.currentTimeMillis());
    }

    @Query("SELECT u FROM User u WHERE u.email = :email AND u.enabled = true")
    public Optional<User> findValidEnabledUserByEmail(String email);

}
