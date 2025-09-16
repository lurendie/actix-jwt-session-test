
# 本项目是魔改版 ,不是项目actix-jwt-session原作者,项目存在以下改动 
```rust
impl actix_web::ResponseError for Error {
    fn status_code(&self) -> actix_web::http::StatusCode {
        match self {
            Self::RedisConn => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            _ => actix_web::http::StatusCode::OK,
        }
    }

    fn error_response(&self) -> actix_web::HttpResponse<actix_web::body::BoxBody> {
        HttpResponse::build(self.status_code())
            .json(serde_json::json!({"code":401,"msg":"非法请求,请登录后再试!"}))
    }
}
```

改动后,当发生错误时,不会直接返回401状态码 ,而是返回200状态码,并返回一个json数据,数据中包含错误信息;