use async_trait::async_trait;
use aws_sdk_lambda::Client;
use aws_types::SdkConfig;
use futures::StreamExt;
use itertools::Itertools;

use crate::security::{SecurityGroups, SecurityGroupsProvider};

pub struct LambdaGroups {}

#[async_trait]
impl SecurityGroupsProvider<SdkConfig> for LambdaGroups {
    async fn load(config: &SdkConfig) -> SecurityGroups {
        let client = Client::new(config);
        let group_ids = client
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
            .collect::<Vec<_>>()
            .await;

        SecurityGroups::create_from_group_ids(
            format!("lambda@{}", config.region().unwrap()),
            group_ids.into_iter(),
        )
    }
}
