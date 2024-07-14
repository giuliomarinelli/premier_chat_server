package backend.app.premier_chat.exception_handling;

public class BadRequestException extends RuntimeException {

    public BadRequestException() {}

    public BadRequestException(String message) {
        super(message);
    }

}
