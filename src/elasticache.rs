use std::collections::HashSet;

use async_trait::async_trait;
use aws_sdk_elasticache::Client;
use futures::StreamExt;
use itertools::Itertools;

use crate::security::KnownSecurityGroups;

pub struct ElasticacheGroups {
    client: Client,
}

#[async_trait]
impl KnownSecurityGroups for ElasticacheGroups {
    fn source_name() -> &'static str {
        "elasticache"
    }

    fn from_config(config: aws_types::SdkConfig) -> Self {
        let client = Client::new(&config);
        Self { client }
    }

    async fn load_security_groups(&self) -> HashSet<String> {
        self.client
            .describe_cache_clusters()
            .into_paginator()
            .items()
            .send()
            .flat_map(|item| {
                let cluster = item.unwrap();
                let val = itertools::chain(
                    cluster.security_groups().into_iter().flat_map(|x| {
                        x.into_iter()
                            .map(|x| x.security_group_id().unwrap().to_owned())
                    }),
                    cluster.cache_security_groups().into_iter().flat_map(|x| {
                        x.into_iter()
                            .map(|x| x.cache_security_group_name().unwrap().to_owned())
                    }),
                )
                .collect_vec();
                futures::stream::iter(val)
            })
            .collect::<HashSet<_>>()
            .await
    }
}
