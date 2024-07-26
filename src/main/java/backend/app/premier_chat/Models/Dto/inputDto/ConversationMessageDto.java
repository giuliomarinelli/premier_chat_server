package backend.app.premier_chat.Models.Dto.inputDto;

import backend.app.premier_chat.Models.mongo_db_documents.Conversation;

import java.util.LinkedHashSet;
import java.util.UUID;

public record ConversationMessageDto(

        UUID fromId,

        UUID toId,

        String body,

        LinkedHashSet<Conversation.Message.FileAttachment>attachments


) {}
