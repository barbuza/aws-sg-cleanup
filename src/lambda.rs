use std::collections::HashSet;

use async_trait::async_trait;
use aws_sdk_lambda::Client;
use futures::StreamExt;
use itertools::Itertools;

use crate::security::KnownSecurityGroups;

pub struct LambdaGroups {
    client: Client,
}

#[async_trait]
impl KnownSecurityGroups for LambdaGroups {
    fn source_name() -> &'static str {
        "lambda"
    }

    fn from_config(config: aws_types::SdkConfig) -> Self {
        let client = Client::new(&config);
        Self { client }
    }

    async fn load_security_groups(&self) -> HashSet<String> {
        self.client
            .list_functions()
            .into_paginator()
            .items()
            .send()
            .flat_map(|item| {
                let groups = item
                    .unwrap()
                    .vpc_config()
                    .map(|vpc_config| {
                        vpc_config
                            .security_group_ids()
                            .unwrap_or_default()
                            .iter()
                            .map(|group_id| group_id.to_owned())
                            .collect_vec()
                    })
                    .unwrap_or_default();
                futures::stream::iter(groups)
            })
            .collect::<HashSet<_>>()
            .await
    }
}
