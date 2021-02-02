package org.apache.rocketmq.example.my.base;

/**
 * @Description : 一些常量
 * @Author : xin
 * @Created : 2021-02-02 1:33 下午
 */
public interface Constants {
    String topic = "TopicTest";
    String namesrv_addr = "127.0.0.1:9876";
    String tags = "TagA";
    String producer_group = "xin_test_producer_group";
    String consumer_group = "xin_test_consumer_group";
    String sub_expression = "*";
}
