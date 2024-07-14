package backend.app.premier_chat.Models.Dto.outputDto;

import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;

import java.sql.Timestamp;
import java.time.LocalDateTime;

@Data
@NoArgsConstructor
public class ConfirmOutputDto {

    private int statusCode;
    private Timestamp timestamp;
    private String message;

    public ConfirmOutputDto(String message, HttpStatus httpStatus) {
        this.message = message;
        this.statusCode = httpStatus.value();
        timestamp = Timestamp.valueOf(LocalDateTime.now());
    }

}
