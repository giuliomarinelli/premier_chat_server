package backend.app.premier_chat.exception_handling;

import lombok.Data;
import org.springframework.http.HttpStatus;

import java.sql.Timestamp;
import java.time.LocalDateTime;

@Data
public class ErrorResDto {

    private int status;
    private Timestamp timestamp;
    private String error;
    private String message;

    public ErrorResDto(HttpStatus status, String error, String message) {
        this.status = status.value();
        this.error = error;
        this.message = message;
        timestamp = Timestamp.valueOf(LocalDateTime.now());
    }
}
