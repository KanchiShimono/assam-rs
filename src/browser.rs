use anyhow::{Context, Error, Result};
use base64::{Engine as _, engine::general_purpose};
use chromiumoxide::cdp::browser_protocol::network::{EnableParams, EventRequestWillBeSent};
use chromiumoxide::{Browser, BrowserConfig};
use futures::StreamExt;
use std::{fs, path::Path, str, sync::Arc, time::Duration};
use tokio::sync::oneshot;
use tokio::time;
use tracing::info;
use url::form_urlencoded;
use urlencoding;

use crate::constants::AWS_SAML_ENDPOINT;

const BROWSER_TIMEOUT: Duration = Duration::from_secs(300);

pub async fn authenticate(
    saml_request: &str,
    tenant_id: &str,
    user_data_dir: &Path,
) -> Result<String> {
    info!("Starting browser authentication flow");

    let mut browser = launch_browser(user_data_dir).await?;

    let result = time::timeout(
        BROWSER_TIMEOUT,
        capture_saml_response(&browser, saml_request, tenant_id),
    )
    .await
    .context("Authentication timed out")??;

    browser.close().await.ok();
    browser.wait().await.ok();

    Ok(result)
}

async fn launch_browser(user_data_dir: &Path) -> Result<Browser> {
    fs::create_dir_all(user_data_dir)?;

    let config = BrowserConfig::builder()
        .user_data_dir(user_data_dir)
        .with_head()
        .viewport(None)
        .args(vec![
            "--no-first-run",
            "--no-default-browser-check",
            "--start-maximized",
            "--disable-blink-features=AutomationControlled", // Prevent detection of automation
            "--no-startup-window",                           // Prevent automatic new tab on startup
        ])
        .build()
        .map_err(Error::msg)?;

    let (browser, mut handler) = Browser::launch(config)
        .await
        .context("Failed to launch Chrome")?;

    tokio::spawn(async move { while handler.next().await.is_some() {} });

    Ok(browser)
}

async fn capture_saml_response(
    browser: &Browser,
    saml_request: &str,
    tenant_id: &str,
) -> Result<String> {
    let page = browser.new_page("about:blank").await?;
    page.execute(EnableParams::default()).await?;

    let (tx, rx) = oneshot::channel();

    // Start monitoring network events
    let page_clone = page.clone();
    tokio::spawn(async move {
        if let Ok(mut events) = page_clone.event_listener::<EventRequestWillBeSent>().await {
            while let Some(event) = events.next().await {
                if let Some(saml) = extract_saml(&event) {
                    let _ = tx.send(saml);
                    return;
                }
            }
        }
    });

    // Navigate to login page
    let url = format!(
        "https://login.microsoftonline.com/{}/saml2?SAMLRequest={}",
        tenant_id,
        urlencoding::encode(saml_request)
    );

    info!("Navigating to Azure Entra ID login page");
    page.goto(&url).await?;
    info!("Browser opened. Please complete authentication in the browser window.");

    // Wait for SAML response
    rx.await
        .map_err(|_| anyhow::anyhow!("SAML response channel closed"))
}

fn extract_saml(event: &Arc<EventRequestWillBeSent>) -> Option<String> {
    if event.request.url != AWS_SAML_ENDPOINT || !event.request.has_post_data.unwrap_or(false) {
        return None;
    }

    event
        .request
        .post_data_entries
        .as_ref()
        .and_then(|entries| {
            let data = entries
                .iter()
                .filter_map(|e| e.bytes.as_ref())
                .filter_map(|b| str::from_utf8(b.as_ref()).ok())
                .collect::<String>();

            // SAMLレスポンスは、サーバー実装によって異なる形式で送信される場合がある：
            // 1. 通常のURLエンコード形式: "SAMLResponse=xxxxx&RelayState=yyy"
            // 2. 全体がBase64エンコード: "U0FNTFJlc3BvbnNlPXh4eHh4..." (デコード後に1の形式)
            //
            // まず通常のURLエンコード形式でパースを試み、失敗した場合は
            // Base64デコード後に再度パースを試みる
            parse_saml_response(&data).or_else(|| try_decode_and_parse(&data))
        })
}

fn parse_saml_response(data: &str) -> Option<String> {
    form_urlencoded::parse(data.as_bytes())
        .find(|(k, _)| k == "SAMLResponse")
        .map(|(_, v)| v.to_string())
}

fn try_decode_and_parse(data: &str) -> Option<String> {
    general_purpose::STANDARD
        .decode(data)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .as_deref()
        .and_then(parse_saml_response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chromiumoxide::cdp::browser_protocol::network::{
        Initiator, InitiatorType, PostDataEntry, Request as CdpRequest, RequestReferrerPolicy,
        ResourcePriority, ResourceType,
    };

    #[test]
    fn test_parse_saml_response() {
        // 正常系: 標準的なURLエンコード形式
        assert_eq!(
            parse_saml_response("SAMLResponse=test123&other=value"),
            Some("test123".to_string())
        );

        // SAMLResponseが最初のパラメータ
        assert_eq!(
            parse_saml_response("SAMLResponse=first&other=value"),
            Some("first".to_string())
        );

        // SAMLResponseが最後のパラメータ
        assert_eq!(
            parse_saml_response("other=value&SAMLResponse=last"),
            Some("last".to_string())
        );

        // SAMLResponseのみ
        assert_eq!(
            parse_saml_response("SAMLResponse=only"),
            Some("only".to_string())
        );

        // 異常系: SAMLResponseなし
        assert_eq!(parse_saml_response("other=value"), None);
        assert_eq!(parse_saml_response(""), None);

        // 値が空の場合でも返す（実際のSAMLでは異常だが、パーサーは値を返す）
        assert_eq!(
            parse_saml_response("SAMLResponse=&other=value"),
            Some("".to_string())
        );

        // 特殊文字を含む値（URLエンコードされた値）
        assert_eq!(
            parse_saml_response("SAMLResponse=test%2B123%3D%3D"),
            Some("test+123==".to_string())
        );
    }

    #[test]
    fn test_decode_and_parse() {
        // 正常系: Base64エンコードされたURLエンコード形式
        let data = "SAMLResponse=encoded_value&RelayState=state";
        let encoded = general_purpose::STANDARD.encode(data);
        assert_eq!(
            try_decode_and_parse(&encoded),
            Some("encoded_value".to_string())
        );

        // 異常系: 不正なBase64
        assert_eq!(try_decode_and_parse("invalid base64!@#"), None);

        // Base64は正しいがSAMLResponseがない
        let data_no_saml = "other=value";
        let encoded_no_saml = general_purpose::STANDARD.encode(data_no_saml);
        assert_eq!(try_decode_and_parse(&encoded_no_saml), None);

        // 空文字列
        assert_eq!(try_decode_and_parse(""), None);

        // Base64デコード後が不正なUTF-8（バイナリデータ）
        let invalid_utf8 = general_purpose::STANDARD.encode([0xFF, 0xFE, 0xFD]);
        assert_eq!(try_decode_and_parse(&invalid_utf8), None);
    }

    #[test]
    fn test_extract_saml_success() {
        // 正常系: AWS SAMLエンドポイントへのPOSTリクエスト
        let request = CdpRequest {
            url: AWS_SAML_ENDPOINT.to_string(),
            url_fragment: None,
            method: "POST".to_string(),
            headers: Default::default(),
            has_post_data: Some(true),
            post_data_entries: Some(vec![PostDataEntry {
                bytes: Some(
                    "SAMLResponse=test_saml_response&RelayState=test_state"
                        .to_string()
                        .into(),
                ),
            }]),
            mixed_content_type: None,
            initial_priority: ResourcePriority::VeryLow,
            referrer_policy: RequestReferrerPolicy::StrictOriginWhenCrossOrigin,
            is_link_preload: None,
            trust_token_params: None,
            is_same_site: None,
        };

        let event = Arc::new(EventRequestWillBeSent {
            request_id: Default::default(),
            loader_id: Default::default(),
            document_url: String::new(),
            request,
            timestamp: Default::default(),
            wall_time: Default::default(),
            initiator: Initiator::new(InitiatorType::Parser),
            redirect_has_extra_info: false,
            redirect_response: None,
            r#type: Some(ResourceType::Document),
            frame_id: None,
            has_user_gesture: None,
        });

        assert_eq!(extract_saml(&event), Some("test_saml_response".to_string()));
    }

    #[test]
    fn test_extract_saml_base64_encoded_body() {
        // Base64エンコードされたPOSTボディ
        let post_data = "SAMLResponse=base64_encoded_saml";
        let encoded_data = general_purpose::STANDARD.encode(post_data);

        let request = CdpRequest {
            url: AWS_SAML_ENDPOINT.to_string(),
            url_fragment: None,
            method: "POST".to_string(),
            headers: Default::default(),
            has_post_data: Some(true),
            post_data_entries: Some(vec![PostDataEntry {
                bytes: Some(encoded_data.into()),
            }]),
            mixed_content_type: None,
            initial_priority: ResourcePriority::VeryLow,
            referrer_policy: RequestReferrerPolicy::StrictOriginWhenCrossOrigin,
            is_link_preload: None,
            trust_token_params: None,
            is_same_site: None,
        };

        let event = Arc::new(EventRequestWillBeSent {
            request_id: Default::default(),
            loader_id: Default::default(),
            document_url: String::new(),
            request,
            timestamp: Default::default(),
            wall_time: Default::default(),
            initiator: Initiator::new(InitiatorType::Parser),
            redirect_has_extra_info: false,
            redirect_response: None,
            r#type: Some(ResourceType::Document),
            frame_id: None,
            has_user_gesture: None,
        });

        assert_eq!(
            extract_saml(&event),
            Some("base64_encoded_saml".to_string())
        );
    }

    #[test]
    fn test_extract_saml_wrong_url() {
        // 異なるURLの場合
        let request = CdpRequest {
            url: "https://example.com/other".to_string(),
            url_fragment: None,
            method: "POST".to_string(),
            headers: Default::default(),
            has_post_data: Some(true),
            post_data_entries: Some(vec![PostDataEntry {
                bytes: Some("SAMLResponse=test".to_string().into()),
            }]),
            mixed_content_type: None,
            initial_priority: ResourcePriority::VeryLow,
            referrer_policy: RequestReferrerPolicy::StrictOriginWhenCrossOrigin,
            is_link_preload: None,
            trust_token_params: None,
            is_same_site: None,
        };

        let event = Arc::new(EventRequestWillBeSent {
            request_id: Default::default(),
            loader_id: Default::default(),
            document_url: String::new(),
            request,
            timestamp: Default::default(),
            wall_time: Default::default(),
            initiator: Initiator::new(InitiatorType::Parser),
            redirect_has_extra_info: false,
            redirect_response: None,
            r#type: Some(ResourceType::Document),
            frame_id: None,
            has_user_gesture: None,
        });

        assert_eq!(extract_saml(&event), None);
    }

    #[test]
    fn test_extract_saml_no_post_data() {
        // POSTデータがない場合
        let request = CdpRequest {
            url: AWS_SAML_ENDPOINT.to_string(),
            url_fragment: None,
            method: "GET".to_string(),
            headers: Default::default(),
            has_post_data: Some(false),
            post_data_entries: None,
            mixed_content_type: None,
            initial_priority: ResourcePriority::VeryLow,
            referrer_policy: RequestReferrerPolicy::StrictOriginWhenCrossOrigin,
            is_link_preload: None,
            trust_token_params: None,
            is_same_site: None,
        };

        let event = Arc::new(EventRequestWillBeSent {
            request_id: Default::default(),
            loader_id: Default::default(),
            document_url: String::new(),
            request,
            timestamp: Default::default(),
            wall_time: Default::default(),
            initiator: Initiator::new(InitiatorType::Parser),
            redirect_has_extra_info: false,
            redirect_response: None,
            r#type: Some(ResourceType::Document),
            frame_id: None,
            has_user_gesture: None,
        });

        assert_eq!(extract_saml(&event), None);
    }

    #[test]
    fn test_extract_saml_empty_post_data_entries() {
        // POSTデータエントリーが空の場合
        let request = CdpRequest {
            url: AWS_SAML_ENDPOINT.to_string(),
            url_fragment: None,
            method: "POST".to_string(),
            headers: Default::default(),
            has_post_data: Some(true),
            post_data_entries: Some(vec![]),
            mixed_content_type: None,
            initial_priority: ResourcePriority::VeryLow,
            referrer_policy: RequestReferrerPolicy::StrictOriginWhenCrossOrigin,
            is_link_preload: None,
            trust_token_params: None,
            is_same_site: None,
        };

        let event = Arc::new(EventRequestWillBeSent {
            request_id: Default::default(),
            loader_id: Default::default(),
            document_url: String::new(),
            request,
            timestamp: Default::default(),
            wall_time: Default::default(),
            initiator: Initiator::new(InitiatorType::Parser),
            redirect_has_extra_info: false,
            redirect_response: None,
            r#type: Some(ResourceType::Document),
            frame_id: None,
            has_user_gesture: None,
        });

        assert_eq!(extract_saml(&event), None);
    }

    #[test]
    fn test_extract_saml_invalid_utf8() {
        // 不正なUTF-8データ
        let request = CdpRequest {
            url: AWS_SAML_ENDPOINT.to_string(),
            url_fragment: None,
            method: "POST".to_string(),
            headers: Default::default(),
            has_post_data: Some(true),
            post_data_entries: Some(vec![PostDataEntry {
                bytes: Some(general_purpose::STANDARD.encode([0xFF, 0xFE, 0xFD]).into()),
            }]),
            mixed_content_type: None,
            initial_priority: ResourcePriority::VeryLow,
            referrer_policy: RequestReferrerPolicy::StrictOriginWhenCrossOrigin,
            is_link_preload: None,
            trust_token_params: None,
            is_same_site: None,
        };

        let event = Arc::new(EventRequestWillBeSent {
            request_id: Default::default(),
            loader_id: Default::default(),
            document_url: String::new(),
            request,
            timestamp: Default::default(),
            wall_time: Default::default(),
            initiator: Initiator::new(InitiatorType::Parser),
            redirect_has_extra_info: false,
            redirect_response: None,
            r#type: Some(ResourceType::Document),
            frame_id: None,
            has_user_gesture: None,
        });

        assert_eq!(extract_saml(&event), None);
    }

    #[test]
    fn test_extract_saml_multiple_post_data_entries() {
        // 複数のPOSTデータエントリー（実際のブラウザでは起こりうる）
        let request = CdpRequest {
            url: AWS_SAML_ENDPOINT.to_string(),
            url_fragment: None,
            method: "POST".to_string(),
            headers: Default::default(),
            has_post_data: Some(true),
            post_data_entries: Some(vec![
                PostDataEntry {
                    bytes: Some("SAMLResponse=part1".to_string().into()),
                },
                PostDataEntry {
                    bytes: Some("&RelayState=state".to_string().into()),
                },
            ]),
            mixed_content_type: None,
            initial_priority: ResourcePriority::VeryLow,
            referrer_policy: RequestReferrerPolicy::StrictOriginWhenCrossOrigin,
            is_link_preload: None,
            trust_token_params: None,
            is_same_site: None,
        };

        let event = Arc::new(EventRequestWillBeSent {
            request_id: Default::default(),
            loader_id: Default::default(),
            document_url: String::new(),
            request,
            timestamp: Default::default(),
            wall_time: Default::default(),
            initiator: Initiator::new(InitiatorType::Parser),
            redirect_has_extra_info: false,
            redirect_response: None,
            r#type: Some(ResourceType::Document),
            frame_id: None,
            has_user_gesture: None,
        });

        assert_eq!(extract_saml(&event), Some("part1".to_string()));
    }
}
