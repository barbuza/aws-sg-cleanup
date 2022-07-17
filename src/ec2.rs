use std::collections::HashSet;

use async_trait::async_trait;
use aws_sdk_ec2::Client;
use futures::StreamExt;
use itertools::Itertools;

use crate::security::KnownSecurityGroups;

pub struct EC2Groups {
    client: Client,
}

#[async_trait]
impl KnownSecurityGroups for EC2Groups {
    fn source_name() -> &'static str {
        "ec2"
    }

    fn from_config(config: aws_types::SdkConfig) -> Self {
        let client = Client::new(&config);
        Self { client }
    }

    async fn load_security_groups(&self) -> HashSet<String> {
        let instances_groups = self
            .client
            .describe_instances()
            .into_paginator()
            .items()
            .send()
            .flat_map(|res| {
                let reservation = res.unwrap();
                let classic = reservation
                    .groups()
                    .unwrap_or_default()
                    .iter()
                    .map(|group| group.group_id().unwrap().to_owned())
                    .collect_vec();
                let vpc = reservation
                    .instances()
                    .unwrap_or_default()
                    .iter()
                    .flat_map(|instance| {
                        instance
                            .security_groups()
                            .unwrap_or_default()
                            .iter()
                            .map(|group| group.group_id().unwrap().to_owned())
                    })
                    .collect_vec();
                futures::stream::iter(itertools::chain(classic, vpc))
            })
            .collect::<HashSet<_>>()
            .await;

        let eni_groups = self
            .client
            .describe_network_interfaces()
            .into_paginator()
            .items()
            .send()
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .flat_map(|res| {
                let eni = res.unwrap();
                eni.groups()
                    .unwrap_or_default()
                    .iter()
                    .map(|group| group.group_id().unwrap().to_owned())
                    .collect_vec()
            })
            .collect::<HashSet<_>>();

        itertools::chain(instances_groups, eni_groups).collect()
    }
}
