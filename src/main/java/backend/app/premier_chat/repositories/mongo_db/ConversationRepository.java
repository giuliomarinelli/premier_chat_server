package backend.app.premier_chat.repositories.mongo_db;

import backend.app.premier_chat.Models.mongo_db_documents.Conversation;
import org.springframework.data.mongodb.repository.Query;
import org.springframework.data.mongodb.repository.ReactiveMongoRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Repository
public interface ConversationRepository extends ReactiveMongoRepository<Conversation, String> {

    @Query("'participants': {$all: [ { $elemMatch: { 'userId': ?0 } }, { $elemMatch: { 'userId': ?1 } } ] }, participants: $size: 2")
    Mono<Conversation> findByParticipantsExactly(UUID userId1, UUID userId2);

}
