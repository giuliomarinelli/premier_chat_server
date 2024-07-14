package backend.app.premier_chat.exception_handling;

public class InternalServerErrorException extends RuntimeException {

    public InternalServerErrorException() {}

    public InternalServerErrorException(String message) {
        super(message);
    }

}
