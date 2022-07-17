use std::collections::HashSet;

use aws_sdk_elasticloadbalancingv2::Client;
use aws_types::SdkConfig;
use futures::StreamExt;
use itertools::Itertools;

use crate::security::KnownSecurityGroups;

pub struct ALBSGroups {
    client: Client,
}

#[async_trait::async_trait]
impl KnownSecurityGroups for ALBSGroups {
    fn source_name() -> &'static str {
        "alb"
    }

    fn from_config(config: SdkConfig) -> Self {
        let client = Client::new(&config);
        Self { client }
    }

    async fn load_security_groups(&self) -> HashSet<String> {
        self.client
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
            .collect::<HashSet<_>>()
            .await
    }
}
