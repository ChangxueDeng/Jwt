package org.example.backend.controller.exception;


import jakarta.validation.ValidationException;
import lombok.extern.slf4j.Slf4j;
import org.example.backend.entity.ResultBean;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@Slf4j
@RestControllerAdvice
public class ValidationController {
    @ExceptionHandler(ValidationException.class)
    public ResultBean<Void> validationException(ValidationException exception){
        log.warn("Resolve [{} : {}]", exception.getClass(), exception.getMessage());
        return ResultBean.failure(400, "请求参数有误");
    }
}
