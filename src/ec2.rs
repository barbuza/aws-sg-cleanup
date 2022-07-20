use async_trait::async_trait;
use aws_sdk_ec2::Client;
use aws_types::SdkConfig;
use futures::StreamExt;
use itertools::Itertools;

use crate::security::{SecurityGroups, SecurityGroupsProvider};

pub struct EC2Groups {}

#[async_trait]
impl SecurityGroupsProvider<SdkConfig> for EC2Groups {
    async fn load(config: &SdkConfig) -> SecurityGroups {
        let client = Client::new(config);
        let instances_groups = client
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
            .collect::<Vec<_>>();

        let eni_groups = client
            .describe_network_interfaces()
            .into_paginator()
            .items()
            .send()
            .flat_map(|res| {
                let eni = res.unwrap();
                futures::stream::iter(
                    eni.groups()
                        .unwrap_or_default()
                        .iter()
                        .map(|group| group.group_id().unwrap().to_owned())
                        .collect_vec(),
                )
            })
            .collect::<Vec<_>>();

        let (instances_groups, eni_groups) = tokio::join!(instances_groups, eni_groups);

        SecurityGroups::create_from_group_ids(
            format!("ec2@{}", config.region().unwrap()),
            itertools::chain(instances_groups, eni_groups),
        )
    }
}
