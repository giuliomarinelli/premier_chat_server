package backend.app.premier_chat.socketIo;

import backend.app.premier_chat.Models.Dto.inputDto.ConversationMessageDto;
import backend.app.premier_chat.Models.enums.TokenType;
import backend.app.premier_chat.security.JwtUtils;
import backend.app.premier_chat.socketIo.services.ClientService;
import backend.app.premier_chat.socketIo.services.ConversationService;
import backend.app.premier_chat.socketIo.services.SessionService;
import com.corundumstudio.socketio.AckRequest;
import com.corundumstudio.socketio.SocketIOClient;
import com.corundumstudio.socketio.SocketIOServer;
import com.corundumstudio.socketio.listener.ConnectListener;
import com.corundumstudio.socketio.listener.DataListener;
import com.corundumstudio.socketio.listener.DisconnectListener;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.CrossOrigin;
import reactor.core.publisher.Mono;

import java.util.EventListener;
import java.util.Optional;
import java.util.UUID;


@Component
@Log4j2
@CrossOrigin(origins = "http://localhost:4200")
public class Gateway {

    private final JwtUtils jwtUtils;

    private final SocketIOServer socketServer;

    private final SessionService sessionService;

    private final ClientService clientService;

    private final SocketUtils socketUtils;

    private final ConversationService conversationService;

    Gateway(
            JwtUtils jwtUtils,
            SocketIOServer socketServer,
            SessionService sessionService,
            ClientService clientService,
            SocketUtils socketUtils,
            ConversationService conversationService
    ) {
        this.jwtUtils = jwtUtils;
        this.socketServer = socketServer;
        this.sessionService = sessionService;
        this.clientService = clientService;
        this.socketUtils = socketUtils;
        this.conversationService = conversationService;
        this.socketServer.addConnectListener(onUserConnectWithSocket);
        this.socketServer.addDisconnectListener(onUserDisconnectWithSocket);
        this.socketServer.addEventListener("sendMessage", ConversationMessageDto.class, onSendConversationMessage);

//        this.socketServer.addEventListener("messageSendToUser", MessageDTO.class, onSendMessage);

    }


    public ConnectListener onUserConnectWithSocket = new ConnectListener() {
        @Override
        public void onConnect(SocketIOClient client) {
            String wsAccessToken = jwtUtils.extractWsTokensFromContextCookies(client).getAccessToken();
            UUID userId = jwtUtils.extractJwtUsefulClaims(wsAccessToken, TokenType.WS_ACCESS_TOKEN, false).getSub();
            sessionService.add(userId, client.getSessionId());
            clientService.add(client.getSessionId(), client);
            log.info("User {} with socketID = {} connected to socket", userId, client.getSessionId());
        }

    };
    public DisconnectListener onUserDisconnectWithSocket = new DisconnectListener() {
        @Override
        public void onDisconnect(SocketIOClient client) {
            String wsAccessToken = jwtUtils.extractWsTokensFromContextCookies(client).getAccessToken();
            UUID userId = jwtUtils.extractJwtUsefulClaims(wsAccessToken, TokenType.WS_ACCESS_TOKEN, true).getSub();
            sessionService.delete(client.getSessionId());
            clientService.remove(client.getSessionId());
            log.info("User {} with socketID = {} disconnected from socket", userId, client.getSessionId());
        }
    };


    public DataListener<ConversationMessageDto> onSendConversationMessage = new DataListener<>() {

        @Override
        public void onData(SocketIOClient client, ConversationMessageDto messageDto, AckRequest ack) throws Exception {

            Optional<UUID> userIdOpt = socketUtils.findUserIdFromClient(client);

            if (userIdOpt.isEmpty()) {
                client.sendEvent("error", "Forbidden");
                client.disconnect();
                return;
            }

            UUID userId = userIdOpt.get();

            conversationService.sendConversationMessage(messageDto, userId)
                    .doOnSuccess(aVoid -> ack.sendAckData("Message sent successfully"))
                    .doOnError(throwable -> {
                        client.sendEvent("error", "Message sending failed");
                        throwable.printStackTrace(); // Log the error
                    })
                    .subscribe(); // Subscribe to start the process
        }
    };

};




//    public DataListener<MessageDTO> onSendMessage = new DataListener<>() {
//        @Override
//        public void onData(SocketIOClient client, MessageDTO messageDTO, AckRequest acknowledge) throws Exception {
//
//            assert userRp.findById(getUserId(client)).isPresent();
//            User senderUser = userRp.findById(getUserId(client)).get();
//
//            User recipientUser = userRp.findById(messageDTO.recipientUserId()).orElseThrow(
//                    () -> new Exception("recipient user not found")
//            );
//
//
//            boolean isRecipientUserOnLine = sessionSvc.isOnLine(recipientUser.getId());
////            log.info(isRecipientUserOnLine);
//
////            log.info(senderUser.getId() + " " + recipientUser.getId());
//
//
//            Order order = orderRp.findById(messageDTO.orderId()).orElse(null);
//
//
//            Message message = new Message(senderUser, recipientUser, order, messageDTO.message(), isRecipientUserOnLine);
//
//
//            messageRp.save(message);
//
//            if (isRecipientUserOnLine) {
//                messageSvc.sendMessageToClient(message);
//            }


//            log.info(message.getSenderUser().getId() + " user sent message to user " + message.getRecipientUser().getId() + " and message is " + message.getMessage());


//            /**
//             * After sending message to target user we can send acknowledge to sender
//             */
//            acknowledge.sendAckData("Message sent to target user successfully");
//        }
//    };



