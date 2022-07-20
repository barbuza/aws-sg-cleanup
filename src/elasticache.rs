use async_trait::async_trait;
use aws_sdk_elasticache::Client;
use aws_types::SdkConfig;
use futures::StreamExt;
use itertools::Itertools;

use crate::security::{SecurityGroups, SecurityGroupsProvider};

pub struct ElasticacheGroups {}

#[async_trait]
impl SecurityGroupsProvider<SdkConfig> for ElasticacheGroups {
    async fn load(config: &SdkConfig) -> SecurityGroups {
        let client = Client::new(config);
        let group_ids = client
            .describe_cache_clusters()
            .into_paginator()
            .items()
            .send()
            .flat_map(|item| {
                let cluster = item.unwrap();
                let val = itertools::chain(
                    cluster
                        .security_groups()
                        .into_iter()
                        .flat_map(|x| x.iter().map(|x| x.security_group_id().unwrap().to_owned())),
                    cluster.cache_security_groups().into_iter().flat_map(|x| {
                        x.iter()
                            .map(|x| x.cache_security_group_name().unwrap().to_owned())
                    }),
                )
                .collect_vec();
                futures::stream::iter(val)
            })
            .collect::<Vec<_>>()
            .await;

        SecurityGroups::create_from_group_ids(
            format!("elasticache@{}", config.region().unwrap()),
            group_ids.into_iter(),
        )
    }
}
