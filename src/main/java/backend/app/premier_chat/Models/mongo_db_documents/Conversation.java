package backend.app.premier_chat.Models.mongo_db_documents;

import jakarta.persistence.Id;
import lombok.*;
import org.springframework.data.mongodb.core.mapping.Document;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.UUID;

@Document(collection = "conversations")
@Data
@NoArgsConstructor
public class Conversation {

    @Id
    @Setter(AccessLevel.NONE)
    private String _id;

    @Setter(AccessLevel.NONE)
    private List<Participant> participants;

    @Setter(AccessLevel.NONE)
    private List<Message> messages;

    public Conversation(List<Participant> participants) {
        if (participants.size() != 2)
            throw new IllegalArgumentException("Conversation partecipants list must contain exactly 2 participants");
        this.participants = participants;
    }

    @Data
    @NoArgsConstructor
    public static class Participant {

        private UUID userId;
        private String username;
        private String completeName;

        public Participant(UUID userId, String username, String firstName, String lastName) {
            this.userId = userId;
            this.username = username;
            this.completeName = firstName + " " + lastName;
        }

    }

    @Data
    @NoArgsConstructor
    public static class Message {

        private UUID fromId;
        private UUID toId;
        private String body;
        private boolean read;
        private boolean wasToUserOffline;
        private long timestamp;
        private LinkedHashSet<FileAttachment> attachments;

        public Message(
                UUID fromId,
                UUID toId,
                String body,
                boolean wasToUserOffLine
        ) {
            this.fromId = fromId;
            this.toId = toId;
            this.body = body;
            this.wasToUserOffline = wasToUserOffLine;
            read = false;
            timestamp = System.currentTimeMillis();
            attachments = new LinkedHashSet<>();
        }

        public Message(
                UUID fromId,
                UUID toId,
                String body,
                boolean wasToUserOffLine,
                LinkedHashSet<FileAttachment> fileAttachments
        ) {
            this.fromId = fromId;
            this.toId = toId;
            this.body = body;
            read = false;
            this.wasToUserOffline = wasToUserOffLine;
            timestamp = System.currentTimeMillis();
            attachments = fileAttachments;
        }

        @Data
        @NoArgsConstructor
        @AllArgsConstructor
        public static class FileAttachment {

            private String fileName;
            private String fileType;
            private String fileUrl;

        }

    }


}
