package backend.app.premier_chat.Models.mongo_db_documents;

import jakarta.persistence.Id;
import lombok.*;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import java.util.ArrayList;
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

    @Field
    @Setter(AccessLevel.NONE)
    private List<Participant> participants;

    @Field
    private List<Message> messages;

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
        private long timestamp;
        private LinkedHashSet<FileAttachment> attachments;

        public Message(UUID fromId, UUID toId, String body) {
            this.fromId = fromId;
            this.toId = toId;
            this.body = body;
            timestamp = System.currentTimeMillis();
            attachments = new LinkedHashSet<>();
        }

        public Message(UUID fromId, UUID toId, String body, LinkedHashSet<FileAttachment> fileAttachments) {
            this.fromId = fromId;
            this.toId = toId;
            this.body = body;
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
