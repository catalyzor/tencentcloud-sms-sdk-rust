
use chrono::prelude::*;
use hmac::{Hmac, Mac, NewMac};
use sha2::{Sha256,Digest};
// use serde_json::json;
use serde::{Serialize,Deserialize};
use log::{info,error};
use dotenv::dotenv;

// #[derive(Serialize, Deserialize)]
// struct Msg<'a> {
//     Sign: &'a str,
//     PhoneNumberSet: Vec<String>,
//     TemplateID: &'a str,
//     SmsSdkAppid: &'a str,
//     TemplateParamSet: Vec<String>,
// }

#[async_std::main]
async fn main() -> surf::Result<()>{
    dotenv().ok();
    env_logger::init();
    let domain = "cvm.tencentcloudapi.com";
    // let domain = "sms.tencentcloudapi.com";
    let url = format!("https://{}",domain);
    let client = surf::client();
    let time = Utc.timestamp(1551113065,0);
    // let time = Utc::now();
    // let time = Utc.timestamp(1618564306, 0);
    let secret_id = "AKIDz8krbsJ5yKBZQpn74WFkmLPx3*******";
    let secret_key = "Gu5t9xGARNpq86cd98joQYCN3*******";
    let payload = "{\"Limit\": 1, \"Filters\": [{\"Values\": [\"\\u672a\\u547d\\u540d\"], \"Name\": \"instance-name\"}]}";
    // let payload = "{}";
    let algorithm = "TC3-HMAC-SHA256";
    let action = "DescribeZones";
    // let action = "SendSms";
    // let service = "sms";
    let service = "cvm";
    // let version = "2019-07-11";
    let version = "2017-03-12";
    let content_type = "application/json; charset=utf-8";
    // let content_type = "application/json";
    let credential_scope = format!("{}/{}/{}",time.format("%Y-%m-%d"),service,"tc3_request");
    let signed_headers = "content-type;host";
    let mut hasher = Sha256::new();
    hasher.update(&payload);
    let result = hasher.finalize();
    info!("sha256 1: {}",hex::encode(result));
    let request_str = format!("{}\n{}\n{}\n{}\n{}\n{}", 
        "POST", "/", "", format!("content-type:{}\nhost:{}\n",content_type,domain),signed_headers,hex::encode(result));
    info!("request_str: {}", request_str);
    hasher = Sha256::new();
    hasher.update(request_str);
    let result1 = hasher.finalize();
    info!("sha256 2: {}",hex::encode(result1));
    let string_to_sign = format!("{}\n{}\n{}\n{}",algorithm,time.timestamp().to_string(),credential_scope,hex::encode(result1));
    info!("string_to_sign: {}",string_to_sign);
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_varkey((format!("TC3{}",secret_key)).as_bytes()).expect("HMAC can take key of any size");
    mac.update(time.format("%Y-%m-%d").to_string().as_bytes());
    let secret_date = mac.finalize();
    mac = HmacSha256::new_varkey(&secret_date.into_bytes()).expect("HMAC can take key of any size");
    mac.update(service.as_bytes());
    let secret_service = mac.finalize();
    mac = HmacSha256::new_varkey(&secret_service.into_bytes()).expect("HMAC can take key of any size");
    mac.update(b"tc3_request");
    let secret_signing = mac.finalize();
    mac = HmacSha256::new_varkey(&secret_signing.into_bytes()).expect("HMAC can take key of any size");
    mac.update(string_to_sign.as_bytes());
    let signature = mac.finalize();
    let signature_str = hex::encode(&signature.into_bytes());
    info!("signature: {}", signature_str);

    let authorization = format!("{} Credential={}/{}, SignedHeaders={}, Signature={}",algorithm,secret_id,credential_scope,signed_headers,signature_str);
    info!("authorization: {}", authorization);
    
    let req = client.post(url)
        .content_type(surf::http::mime::JSON)
        .header("X-TC-Action", action)
        .header("X-TC-Timestamp", time.timestamp().to_string())
        .header("X-TC-Version", version)
        .header("Authorization", authorization)
        // .header("X-TC-Region", "ap-beijing")
        // .header("X-TC-Language", "zh-CN")
        .body(payload)
        .build();
    // println!("content-type: {:?}",req);
    let mut res = client.with(surf::middleware::Logger::new()).send(req).await?;
    info!("{}",res.body_string().await?);
    Ok(())
}
