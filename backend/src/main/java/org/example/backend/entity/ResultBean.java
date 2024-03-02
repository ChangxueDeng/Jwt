package org.example.backend.entity;

import com.alibaba.fastjson2.JSONObject;
import com.alibaba.fastjson2.JSONWriter;
import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class ResultBean<T> {
    private int code;
    private T data;
    private String message;
    private boolean success;


    public static <T> ResultBean<T> success(T data, String message){
        return new ResultBean<>(200, data, message, true);
    }
    public static <T> ResultBean<T> success(String message){
        return new ResultBean<>(200, null, message, true);
    }
    public static <T> ResultBean<T> failure(int code, T data, String message){
        return new ResultBean<>(code, data, message, false);
    }
    public static <T> ResultBean<T> success(){
        return new ResultBean<>(200, null, null, true);
    }
    public static <T> ResultBean<T> failure(int code, String message){
        return new ResultBean<>(code, null, message, false);
    }
    public String asJOSNString(){
        return JSONObject.toJSONString(this, JSONWriter.Feature.WriteNulls);
    }
}
