
# 本项目是魔改版 ,不是项目actix-jwt-session原作者,项目存在以下改动 
## 改动1
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
##改动2 为结构体Extractors<ClaimsType: Claims + std::fmt::Debug>添加new方法 ,用户可自定义jwt验证方法
```rust
pub fn new(
        jwt_extractors: Vec<Arc<dyn SessionExtractor<ClaimsType>>>,
        refresh_extractors: Vec<Arc<dyn SessionExtractor<RefreshToken>>>,
    ) -> Self {
        Self {
            jwt_extractors,
            refresh_extractors,
        }
    }
```

以下是官方实例 但是官方不能创建Extractors结构体导致无法自定义jwt验证方法,已改动
   Extract claims from [actix_web::dev::ServiceRequest]
    
     Examples:
    
     ```
     use actix_web::dev::ServiceRequest;
     use jsonwebtoken::*;
     use actix_jwt_session::*;
     use std::sync::Arc;
     use actix_web::HttpMessage;
     use std::borrow::Cow;
    
     [derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
      pub struct Claims { id: uuid::Uuid, sub: String }
      impl actix_jwt_session::Claims for Claims {
         fn jti(&self) -> uuid::Uuid { self.id }
         fn subject(&self) -> &str { &self.sub }
     }
    
     #[derive(Debug, Clone, Copy, Default)]
     struct ExampleExtractor;
    
     #[async_trait::async_trait(?Send)]
     impl SessionExtractor<Claims> for ExampleExtractor {
         async fn extract_claims(
             &self,
             req: &mut ServiceRequest,
             jwt_encoding_key: Arc<EncodingKey>,
             jwt_decoding_key: Arc<DecodingKey>,
             algorithm: Algorithm,
             storage: SessionStorage,
         ) -> Result<(), Error> {
             if req.peer_addr().unwrap().ip().is_multicast() {
                req.extensions_mut().insert(Authenticated {
                    claims: Arc::new(Claims { id: uuid::Uuid::default(), sub: "HUB".into() }),
                    jwt_encoding_key,
                    algorithm,
                });
             }
             Ok(())
         }
    
         async fn extract_token_text<'req>(&self, req: &'req mut ServiceRequest) -> Option<Cow<'req, str>> { None }
         fn extractor_key(&self) -> Option<(ExtractorKind, Cow<'static, str>)> {None}
     }
     ```


改动后,当发生错误时,不会直接返回401状态码 ,而是返回200状态码,并返回一个json数据,数据中包含错误信息;