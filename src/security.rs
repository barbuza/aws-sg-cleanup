use std::collections::{HashMap, HashSet};

use aws_sdk_ec2::Client;
use aws_types::SdkConfig;
use futures::StreamExt;
use itertools::Itertools;

#[async_trait::async_trait]
pub trait KnownSecurityGroups {
    fn source_name() -> &'static str;
    fn from_config(config: SdkConfig) -> Self;
    async fn load_security_groups(&self) -> HashSet<String>;
}

#[derive(Default, Debug)]
pub struct SecurityGroups {
    pub external_references: HashMap<String, Vec<String>>,
    pub existing_groups: Vec<ExistingGroup>,
}

#[derive(PartialEq, Eq, Clone, Debug)]
pub struct GroupReference {
    pub source: String,
    pub group_id: String,
}

#[derive(Clone, Debug)]
pub struct ExistingGroup {
    pub region: String,
    pub group_id: String,
    pub group_name: String,
    pub group_description: String,
    pub references: HashSet<String>,
}

impl SecurityGroups {
    pub async fn load_existing(sdk_config: SdkConfig) -> Vec<ExistingGroup> {
        Client::new(&sdk_config)
            .describe_security_groups()
            .into_paginator()
            .items()
            .send()
            .map(|item| {
                let group = item.unwrap();
                let group_id = group.group_id().unwrap();

                let references: HashSet<_> = group
                    .ip_permissions()
                    .unwrap_or_default()
                    .iter()
                    .flat_map(|permission| {
                        permission
                            .user_id_group_pairs()
                            .unwrap_or_default()
                            .iter()
                            .map(|x| x.group_id().unwrap().to_owned())
                    })
                    .filter(|x| x != group_id)
                    .collect();

                ExistingGroup {
                    region: sdk_config.region().map(|x| x.as_ref().to_owned()).unwrap(),
                    group_id: group_id.to_owned(),
                    group_name: group.group_name().unwrap().to_owned(),
                    group_description: group.description().unwrap().to_owned(),
                    references,
                }
            })
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .filter(|group| group.group_description != "default VPC security group")
            .collect_vec()
    }

    pub fn collect_referencing_services(
        &self,
        group_id: &str,
        visited: HashSet<String>,
    ) -> HashSet<String> {
        let direct_refs = self
            .external_references
            .get(group_id)
            .unwrap_or(&vec![])
            .iter()
            .map(|x| x.to_string())
            .collect_vec();

        let indirect_refs = self
            .existing_groups
            .iter()
            .filter(|group| {
                group.references.contains(group_id) && !visited.contains(&group.group_id)
            })
            .flat_map(|group| {
                self.collect_referencing_services(&group.group_id, {
                    let mut clone = visited.clone();
                    clone.insert(group_id.to_string());
                    clone
                })
            })
            .collect_vec();

        itertools::chain(direct_refs, indirect_refs).collect()
    }

    pub fn find_unused(&self) -> Vec<&ExistingGroup> {
        self.existing_groups
            .iter()
            .filter(|group| {
                let referenced_by =
                    self.collect_referencing_services(&group.group_id, HashSet::default());
                referenced_by.is_empty()
            })
            .collect_vec()
    }
}
