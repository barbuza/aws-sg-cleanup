use async_trait::async_trait;
use aws_sdk_rds::Client;
use aws_types::SdkConfig;
use futures::StreamExt;
use itertools::Itertools;

use crate::security::{SecurityGroups, SecurityGroupsProvider};

pub struct RDSGroups {}

#[async_trait]
impl SecurityGroupsProvider<SdkConfig> for RDSGroups {
    async fn load(config: &SdkConfig) -> SecurityGroups {
        let client = Client::new(config);
        let db = client
            .describe_db_instances()
            .into_paginator()
            .items()
            .send()
            .flat_map(|item| {
                let db = item.unwrap();
                let vpc = db
                    .vpc_security_groups()
                    .unwrap_or_default()
                    .iter()
                    .map(|group| group.vpc_security_group_id().unwrap().to_owned())
                    .collect_vec();
                let classic = db
                    .db_security_groups()
                    .unwrap_or_default()
                    .iter()
                    .map(|group| group.db_security_group_name().unwrap().to_owned())
                    .collect_vec();
                futures::stream::iter(itertools::chain(vpc, classic))
            })
            .collect::<Vec<_>>();
        let aurora = client
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
                        .iter()
                        .map(|group| group.vpc_security_group_id().unwrap().to_owned())
                        .collect_vec(),
                )
            })
            .collect::<Vec<_>>();

        let (db, aurora) = tokio::join!(db, aurora);

        SecurityGroups::create_from_group_ids(
            format!("rds@{}", config.region().unwrap()),
            itertools::chain(db, aurora),
        )
    }
}
