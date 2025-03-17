package com.movienetscape.authorization.messaging.producer;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.movienetscape.authorization.messaging.event.PasswordResetEvent;
import com.movienetscape.usermanagementservice.messaging.event.UserRegisteredEvent;
import com.movienetscape.usermanagementservice.messaging.event.UserVerifiedEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class KafkaEventProducer {


    private final KafkaTemplate<String, String> kafkaTemplate;
    private final ObjectMapper objectMapper;



    public void publishPasswordResetEvent(PasswordResetEvent passwordResetEvent) {
        try {
            String eventJson = objectMapper.writeValueAsString(passwordResetEvent);
            kafkaTemplate.send("password-reset-topic", eventJson);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Failed to serialize user verified event", e);
        }
    }





}
