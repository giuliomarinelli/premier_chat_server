package backend.app.premier_chat.socketIo.services;

import backend.app.premier_chat.Models.Dto.inputDto.ConversationMessageDto;
import backend.app.premier_chat.Models.entities.User;
import backend.app.premier_chat.Models.mongo_db_documents.Conversation;
import backend.app.premier_chat.exception_handling.BadRequestException;
import backend.app.premier_chat.exception_handling.NotFoundException;
import backend.app.premier_chat.repositories.jpa.UserRepository;
import backend.app.premier_chat.repositories.mongo_db.ConversationRepository;
import com.corundumstudio.socketio.SocketIOClient;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Set;
import java.util.UUID;


@Service
@Log4j2
public class ConversationService {

    private final ConversationRepository conversationRepository;

    private final UserRepository userRepository;

    private final SessionService sessionService;

    private final ClientService clientService;

    public ConversationService(
            ConversationRepository conversationRepository,
            UserRepository userRepository,
            SessionService sessionService,
            ClientService clientService
    ) {
        this.conversationRepository = conversationRepository;
        this.userRepository = userRepository;
        this.sessionService = sessionService;
        this.clientService = clientService;
    }

    public Mono<Boolean> isThereAConversationBetweenTwoUsers(UUID userId1, UUID userId2) {

        return conversationRepository.findByParticipantsExactly(userId1, userId2)
                .hasElement()
                .defaultIfEmpty(false);

    }

    public Mono<Conversation> findConversationBetweenTwoUsers(UUID userId1, UUID userId2) {

        return isThereAConversationBetweenTwoUsers(userId1, userId2)
                .flatMap(exists -> {
                    if (!exists) throw new NotFoundException("Conversation not found");
                    return conversationRepository.findByParticipantsExactly(userId1, userId2);
                });

    }

    public Mono<Conversation.Participant> createParticipant(UUID userId) {

        User user = userRepository.findValidEnabledUserById(userId).orElseThrow(
                () -> new NotFoundException("User with id = " + userId + " not found")
        );

        return Mono.just(new Conversation.Participant(userId, user.getUsername(), user.getFirstName(), user.getLastName()));

    }

    public Mono<Conversation> createConversation(UUID userId1, UUID userId2) {

        return isThereAConversationBetweenTwoUsers(userId1, userId2).flatMap(exists -> {

            if (exists)
                throw new BadRequestException("Conversation with users with id " + userId1 +
                        " and " + userId2 + " already exists");

            Mono<Conversation.Participant> participantMono1 = createParticipant(userId1);
            Mono<Conversation.Participant> participantMono2 = createParticipant(userId2);

            return Mono.zip(participantMono1, participantMono2)
                    .flatMap(tuple -> {

                        Conversation conversation = new Conversation(List.of(tuple.getT1(), tuple.getT2()));

                        return conversationRepository.save(conversation).thenReturn(conversation);

                    });
        });

    }

    public Mono<Void> sendConversationMessage(ConversationMessageDto messageDto, UUID fromId) {
        return isThereAConversationBetweenTwoUsers(fromId, messageDto.toId())
                .flatMap(isThere -> {

                    log.info(isThere);

                    Conversation.Message message = new Conversation.Message(
                            fromId,
                            messageDto.toId(),
                            messageDto.body(),
                            !sessionService.isUserOnLine(messageDto.toId())
                    );

                    log.info(message);

                    Mono<Conversation> conversationMono;

                    if (isThere) {
                        conversationMono = conversationRepository.findByParticipantsExactly(fromId, messageDto.toId());
                    } else {
                        conversationMono = createConversation(fromId, messageDto.toId());
                    }

                    return conversationMono.flatMap(conversation -> {
                        conversation.getMessages().add(message);
                        return conversationRepository.save(conversation)
                                .then(Mono.fromRunnable(() -> {
                                    if (sessionService.isUserOnLine(messageDto.toId())) {
                                        Set<UUID> sessionIds = sessionService.getSessionIdsFromUserId(messageDto.toId());
                                        for (UUID sessionId : sessionIds) {
                                            SocketIOClient client = clientService.get(sessionId);
                                            client.sendEvent("message", message);
                                        }
                                    }
                                }));
                    });
                });
    }

}
