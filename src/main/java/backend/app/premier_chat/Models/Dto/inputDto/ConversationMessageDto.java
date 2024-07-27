package backend.app.premier_chat.Models.Dto.inputDto;

import backend.app.premier_chat.Models.mongo_db_documents.Conversation;
import jakarta.validation.constraints.NotBlank;

import java.util.LinkedHashSet;
import java.util.UUID;

public record ConversationMessageDto(


        @NotBlank
        UUID toId,

        @NotBlank
        String body,

        LinkedHashSet<Conversation.Message.FileAttachment>attachments


) {}
