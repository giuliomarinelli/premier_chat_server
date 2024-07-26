package backend.app.premier_chat.services;

import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

@Service
@Configuration
public class NotificationService {


    private final String twilioPhoneNumber;


    private final String mailDefaultFrom;


    private final JavaMailSenderImpl javaMailSender;

    public NotificationService(
            @Value("${spring.configuration.twilio.phoneNumber}") String twilioPhoneNumber,
            @Value("${spring.configuration.mail.from}") String mailDefaultFrom,
            JavaMailSenderImpl javaMailSender
    ) {
        this.mailDefaultFrom = mailDefaultFrom;
        this.twilioPhoneNumber = twilioPhoneNumber;
        this.javaMailSender = javaMailSender;
    }

    public void sendSms(String toPhoneNumber, String messageBody) {
        Message message = Message.creator(
                        new PhoneNumber(toPhoneNumber),
                        new PhoneNumber(twilioPhoneNumber),
                        messageBody)
                .create();
    }

    public void sendEmail(String to, String subject, String text) {
        SimpleMailMessage msg = new SimpleMailMessage();
        msg.setTo(to);
        msg.setSubject(subject);
        msg.setText(text);
        msg.setFrom(mailDefaultFrom);
        javaMailSender.send(msg);
    }

    public void sendHtmlEmail(String to, String subject, String htmlBody) throws MessagingException {
        MimeMessage message = javaMailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

        helper.setTo(to);
        helper.setSubject(subject);
        helper.setText(htmlBody, true);
        helper.setFrom(mailDefaultFrom);

        javaMailSender.send(message);
    }

}
