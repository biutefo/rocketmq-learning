package org.apache.rocketmq.example.my.producer;

import org.apache.rocketmq.client.exception.MQClientException;
import org.apache.rocketmq.client.producer.DefaultMQProducer;
import org.apache.rocketmq.client.producer.SendResult;
import org.apache.rocketmq.common.message.Message;
import org.apache.rocketmq.example.my.base.Constants;

import java.nio.charset.StandardCharsets;

public class MyProducer implements Constants {
    public static void main(String[] args) throws MQClientException, InterruptedException {
        DefaultMQProducer producer = new DefaultMQProducer(producer_group);
        producer.setNamesrvAddr(namesrv_addr);
        producer.start();
        for (int i = 0; i < 1000; i++) {
            try {
                Message msg = new Message(topic, tags, ("Hello RocketMQ " + i).getBytes(StandardCharsets.UTF_8));
                SendResult sendResult = producer.send(msg);
                System.out.printf("%s%n", sendResult);
            } catch (Exception e) {
                e.printStackTrace();
                Thread.sleep(1000);
            }
        }
        producer.shutdown();
    }
}
