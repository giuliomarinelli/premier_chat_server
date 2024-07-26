package backend.app.premier_chat.socketIo.services;

import backend.app.premier_chat.Models.entities.User;
import backend.app.premier_chat.Models.mongo_db_documents.Conversation;
import backend.app.premier_chat.exception_handling.BadRequestException;
import backend.app.premier_chat.exception_handling.NotFoundException;
import backend.app.premier_chat.repositories.jpa.UserRepository;
import backend.app.premier_chat.repositories.mongo_db.ConversationRepository;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.UUID;


@Service
public class ConversationService {

    private final ConversationRepository conversationRepository;

    private final UserRepository userRepository;

    public ConversationService(
            ConversationRepository conversationRepository,
            UserRepository userRepository
    ) {
        this.conversationRepository = conversationRepository;
        this.userRepository = userRepository;
    }

    public Mono<Boolean> isThereAConversationBetweenTwoUsers(UUID userId1, UUID userId2) {

        return conversationRepository.findByParticipantsExactly(userId1, userId2)
                .hasElement()
                .defaultIfEmpty(false);
    }

    public Mono<Conversation> findConversationBetweenTwoUsers(UUID userId1, UUID userId2) {

        return isThereAConversationBetweenTwoUsers(userId1, userId2)
                .flatMap(value -> {
                    if (!value) throw new NotFoundException("Conversation not found");
                    return conversationRepository.findByParticipantsExactly(userId1, userId2);
                });
    }

    public Conversation.Participant createParticipant(UUID userId) {

        User user = userRepository.findValidEnabledUserById(userId).orElseThrow(
                () -> new NotFoundException("User with id = " + userId + " not found")
        );

        return new Conversation.Participant(userId, user.getUsername(), user.getFirstName(), user.getLastName());

    }

    public Mono<Conversation> createConversation(UUID userId1, UUID userId2) {

        return isThereAConversationBetweenTwoUsers(userId1, userId2).flatMap(value -> {

            if (value)
                throw new BadRequestException("Conversation with users with id " + userId1 +
                        " and " + userId2 + " already exists");

            Conversation.Participant participant1 = createParticipant(userId1);
            Conversation.Participant participant2 = createParticipant(userId2);

            Conversation conversation = new Conversation(List.of(participant1, participant2));

            conversationRepository.save(conversation);

            return Mono.just(conversation);

        });

    }

}
