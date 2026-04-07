use super::transport::ensure_success;
use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;
use url::Url;

pub(crate) async fn get_paginated<T: for<'de> Deserialize<'de>>(
    client: &Client,
    base_url: &str,
) -> Result<Vec<T>> {
    let base = Url::parse(base_url)?;
    let mut items = Vec::new();
    let mut page = 1u32;

    loop {
        let mut url = base.clone();
        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("per_page", "100");
            pairs.append_pair("page", &page.to_string());
        }

        let response = client
            .get(url.clone())
            .send()
            .await
            .with_context(|| format!("gitlab GET {}", url.as_str()))?;

        let next_page = response
            .headers()
            .get("X-Next-Page")
            .and_then(|val| val.to_str().ok())
            .and_then(|val| {
                if val.is_empty() {
                    None
                } else {
                    Some(val.to_string())
                }
            });

        let mut page_items: Vec<T> = ensure_success(response, "GET", url.as_str()).await?;
        items.append(&mut page_items);

        match next_page {
            Some(next) => {
                page = next.parse::<u32>().unwrap_or(page + 1);
            }
            None => break,
        }
    }

    Ok(items)
}
