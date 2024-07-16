package backend.app.premier_chat.exception_handling;

public class ForbiddenException extends RuntimeException {

    public ForbiddenException() {}

    public ForbiddenException(String message) {
        super(message);
    }

}
