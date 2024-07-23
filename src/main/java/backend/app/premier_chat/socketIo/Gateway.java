package backend.app.premier_chat.socketIo;

import backend.app.premier_chat.security.JwtUtils;
import com.corundumstudio.socketio.AckRequest;
import com.corundumstudio.socketio.SocketIOClient;
import com.corundumstudio.socketio.SocketIOServer;
import com.corundumstudio.socketio.listener.ConnectListener;
import com.corundumstudio.socketio.listener.DataListener;
import com.corundumstudio.socketio.listener.DisconnectListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.CrossOrigin;

import java.util.List;
import java.util.UUID;

@Component
//@Log4j2
@CrossOrigin(origins = "http://localhost:4200")
public class Gateway {

    private static final Logger log = LoggerFactory.getLogger(Gateway.class);
    private final JwtUtils jwtUtils;

    private final SocketIOServer socketServer;

    Gateway(JwtUtils jwtUtils, SocketIOServer socketServer) {
        this.jwtUtils = jwtUtils;
        this.socketServer = socketServer;
        this.socketServer.addConnectListener(onUserConnectWithSocket);
        this.socketServer.addDisconnectListener(onUserDisconnectWithSocket);

//        this.socketServer.addEventListener("messageSendToUser", MessageDTO.class, onSendMessage);

    }


    public ConnectListener onUserConnectWithSocket = new ConnectListener() {
        @Override
        public void onConnect(SocketIOClient client) {
            log.info("User with socketID = {} connected to socket", client.getSessionId());
        }
    };


    public DisconnectListener onUserDisconnectWithSocket = new DisconnectListener() {
        @Override
        public void onDisconnect(SocketIOClient client) {
            log.info("User with socketID = {} disconnected from socket", client.getSessionId());
        }
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



}