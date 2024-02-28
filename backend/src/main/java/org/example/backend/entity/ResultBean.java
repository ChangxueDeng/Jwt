package org.example.backend.entity;

import com.alibaba.fastjson2.JSONObject;
import com.alibaba.fastjson2.JSONWriter;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.stereotype.Component;

@Data
@AllArgsConstructor
public class ResultBean<T> {
    private int code;
    private T data;
    private String message;
    private boolean success;

    ResultBean(int code, T data){
        this.code = code;
        this.data = data;
    }
    ResultBean(T data){
        this.data = data;
    }
    ResultBean(T data, String message){
        this.data = data;
        this.message = message;
    }

    public static <T> ResultBean<T> success(T data, String message){
        return new ResultBean<T>(200,data,message,true);
    }
    public static <T> ResultBean<T> success(String message){
        return new ResultBean<T>(200,null,message, true);
    }
    public static <T> ResultBean<T> failure(int code, T data, String message){
        return new ResultBean<T>(code, data, message, false);
    }
    public static <T> ResultBean<T> failure(int code, String message){
        return new ResultBean<T>(code, null, message,false);
    }
    public String asJOSNString(){
        return JSONObject.toJSONString(this, JSONWriter.Feature.WriteNulls);
    }
}
