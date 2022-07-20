use aws_sdk_elasticloadbalancingv2::Client;
use aws_types::SdkConfig;
use futures::StreamExt;
use itertools::Itertools;

use crate::security::{SecurityGroups, SecurityGroupsProvider};

pub struct ALBGroups {}

#[async_trait::async_trait]
impl SecurityGroupsProvider<SdkConfig> for ALBGroups {
    async fn load(config: &SdkConfig) -> SecurityGroups {
        let client = Client::new(config);
        let group_ids = client
            .describe_load_balancers()
            .into_paginator()
            .items()
            .send()
            .flat_map(|res| {
                let load_balancer = res.unwrap();
                futures::stream::iter(
                    load_balancer
                        .security_groups()
                        .unwrap_or_default()
                        .iter()
                        .map(|group| group.to_owned())
                        .collect_vec(),
                )
            })
            .collect::<Vec<_>>()
            .await;

        SecurityGroups::create_from_group_ids(
            format!("alb@{}", config.region().unwrap()),
            group_ids.into_iter(),
        )
    }
}
