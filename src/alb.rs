use aws_sdk_elasticloadbalancingv2::Client;
use aws_types::SdkConfig;
use futures::StreamExt;
use itertools::Itertools;

use crate::security::{SecurityGroups, SecurityGroupsProvider};

pub struct ALBGroups {
    client: Client,
    region: String,
}

#[async_trait::async_trait]
impl SecurityGroupsProvider<SdkConfig> for ALBGroups {
    fn new(config: &SdkConfig) -> Self {
        let client = Client::new(config);
        Self {
            client,
            region: config.region().unwrap().to_string(),
        }
    }

    async fn load(&self) -> SecurityGroups {
        let group_ids = self
            .client
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

        SecurityGroups::create_from_group_ids(format!("alb@{}", self.region), group_ids.into_iter())
    }
}
