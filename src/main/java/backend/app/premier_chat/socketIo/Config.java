package backend.app.premier_chat.socketIo;


import com.corundumstudio.socketio.Configuration;
import com.corundumstudio.socketio.SocketIOClient;
import com.corundumstudio.socketio.SocketIOServer;
import com.corundumstudio.socketio.listener.ConnectListener;
import com.corundumstudio.socketio.listener.DisconnectListener;
import jakarta.annotation.PreDestroy;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.CrossOrigin;

// Da converire in forma soft-coded
@CrossOrigin(origins = {"http://localhost:4200", "http://localhost:4000"})
@Component
@org.springframework.context.annotation.Configuration
@Log4j2
public class Config {

    @Autowired
    private Auth authorizationListener;

    @Value("${spring.configuration.socket.host}")
    private String SOCKET_HOST;
    @Value("${spring.configuration.socket.port}")
    private int SOCKET_PORT;
    private SocketIOServer server;

    @Bean
    public SocketIOServer socketIOServer() {
        Configuration config = new Configuration();
        config.setHostname(SOCKET_HOST);
        config.setPort(SOCKET_PORT);
        config.setAuthorizationListener(authorizationListener);
        server = new SocketIOServer(config);
        server.start();
        server.addConnectListener(new ConnectListener() {
            @Override
            public void onConnect(SocketIOClient client) {
//                log.info("new user connected with socket " + client.getSessionId());
            }
        });


        server.addDisconnectListener(new DisconnectListener() {
            @Override
            public void onDisconnect(SocketIOClient client) {
//                client.getNamespace().getAllClients().forEach(data -> {
//                    log.info("user disconnected " + data.getSessionId().toString());
//                });
            }
        });
        return server;
    }

    @PreDestroy
    public void stopSocketIOServer() {
        this.server.stop();
    }

}
