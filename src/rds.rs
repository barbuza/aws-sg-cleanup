use std::collections::HashSet;

use async_trait::async_trait;
use aws_sdk_rds::Client;
use futures::StreamExt;
use itertools::Itertools;

use crate::security::KnownSecurityGroups;

pub struct RDSGroups {
    client: Client,
}

#[async_trait]
impl KnownSecurityGroups for RDSGroups {
    fn source_name() -> &'static str {
        "rds"
    }

    fn from_config(config: aws_types::SdkConfig) -> Self {
        let client = Client::new(&config);
        Self { client }
    }

    async fn load_security_groups(&self) -> HashSet<String> {
        let db = self
            .client
            .describe_db_instances()
            .into_paginator()
            .items()
            .send()
            .flat_map(|item| {
                let db = item.unwrap();
                let vpc = db
                    .vpc_security_groups()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|group| group.vpc_security_group_id().unwrap().to_owned())
                    .collect_vec();
                let classic = db
                    .db_security_groups()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|group| group.db_security_group_name().unwrap().to_owned())
                    .collect_vec();
                futures::stream::iter(itertools::chain(vpc, classic))
            })
            .collect::<HashSet<_>>()
            .await;
        let aurora = self
            .client
            .describe_db_clusters()
            .into_paginator()
            .items()
            .send()
            .flat_map(|item| {
                let cluster = item.unwrap();
                futures::stream::iter(
                    cluster
                        .vpc_security_groups()
                        .unwrap_or_default()
                        .into_iter()
                        .map(|group| group.vpc_security_group_id().unwrap().to_owned())
                        .collect_vec(),
                )
            })
            .collect::<HashSet<_>>()
            .await;
        itertools::chain(db, aurora).collect()
    }
}
