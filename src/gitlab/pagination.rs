use super::client::GitLabClient;
use anyhow::Result;
use serde::Deserialize;
use url::Url;

pub(crate) async fn get_paginated<T: for<'de> Deserialize<'de> + Send>(
    client: &GitLabClient,
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

        let (mut page_items, next_page): (Vec<T>, Option<String>) =
            client.get_paginated_page(url.as_str()).await?;
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
