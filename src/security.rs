use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use aws_sdk_ec2::Client;
use aws_types::SdkConfig;
use futures::StreamExt;
use itertools::Itertools;
use maplit::hashmap;

#[async_trait]
pub trait SecurityGroupsProvider<T>
where
    T: Clone,
{
    fn new(config: &T) -> Self;
    async fn load(&self) -> SecurityGroups;
}

type ReferenceServiceName = String;
type GroupId = String;

#[derive(Default, Debug, Clone)]
pub struct SecurityGroups {
    pub external_references: HashMap<GroupId, Vec<ReferenceServiceName>>,
    pub existing_groups: Vec<ExistingGroup>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExistingGroup {
    pub region: String,
    pub group_id: GroupId,
    pub group_name: String,
    pub group_description: String,
    pub references: HashSet<String>,
}

pub struct AWSSecurityGroups {
    client: Client,
    region: String,
}

#[async_trait]
impl SecurityGroupsProvider<SdkConfig> for AWSSecurityGroups {
    fn new(config: &SdkConfig) -> Self {
        let client = Client::new(config);
        Self {
            client,
            region: config.region().unwrap().to_string(),
        }
    }

    async fn load(&self) -> SecurityGroups {
        let existing_groups = self
            .client
            .describe_security_groups()
            .into_paginator()
            .items()
            .send()
            .map(|item| {
                let group = item.unwrap();

                let aws_sdk_ec2::model::SecurityGroup {
                    group_id,
                    group_name,
                    description,
                    ip_permissions,
                    ..
                } = group;
                let group_id = group_id.unwrap();
                let group_name = group_name.unwrap();
                let group_description = description.unwrap();

                let references: HashSet<_> = ip_permissions
                    .unwrap_or_default()
                    .iter()
                    .flat_map(|permission| {
                        permission
                            .user_id_group_pairs()
                            .unwrap_or_default()
                            .iter()
                            .map(|x| x.group_id().unwrap().to_owned())
                    })
                    .filter(|x| *x != group_id)
                    .collect();

                ExistingGroup {
                    region: self.region.clone(),
                    group_id,
                    group_name,
                    group_description,
                    references,
                }
            })
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .filter(|group| group.group_description != "default VPC security group")
            .collect_vec();

        SecurityGroups {
            external_references: hashmap![],
            existing_groups,
        }
    }
}

impl SecurityGroups {
    pub fn create_from_group_ids(source: String, group_ids: impl Iterator<Item = String>) -> Self {
        let mut external_references = hashmap![];
        for item in group_ids.unique() {
            external_references
                .entry(item)
                .or_insert_with(Vec::new)
                .push(source.clone());
        }
        Self {
            external_references,
            existing_groups: vec![],
        }
    }

    pub fn merge(&mut self, other: &SecurityGroups) {
        for (group_id, references) in other.external_references.iter() {
            self.external_references
                .entry(group_id.clone())
                .or_insert_with(Vec::new)
                .extend(references.clone());
        }
        self.existing_groups.extend(other.existing_groups.clone());
    }

    pub fn collect_referencing_services(
        &self,
        group_id: &str,
        visited: HashSet<String>,
    ) -> HashSet<String> {
        let direct_refs = self
            .external_references
            .get(group_id)
            .map_or(vec![], |x| x.clone());

        let mut visited = visited;
        visited.insert(group_id.to_string());

        let indirect_refs = self
            .existing_groups
            .iter()
            .filter(|group| {
                group.references.contains(group_id) && !visited.contains(&group.group_id)
            })
            .flat_map(|group| self.collect_referencing_services(&group.group_id, visited.clone()));

        itertools::chain(direct_refs, indirect_refs).collect()
    }

    pub fn find_unused(&self) -> Vec<&ExistingGroup> {
        self.existing_groups
            .iter()
            .filter(|group| {
                let referenced_by =
                    self.collect_referencing_services(&group.group_id, HashSet::new());
                referenced_by.is_empty()
            })
            .collect_vec()
    }
}

#[cfg(test)]
mod test {

    use std::collections::HashSet;

    use itertools::Itertools;
    use maplit::hashmap;

    use crate::security::ExistingGroup;

    use super::SecurityGroups;

    #[test]
    fn test_merge_id() {
        let mut sg1 = SecurityGroups::default();
        sg1.merge(&SecurityGroups::default());
        assert_eq!(sg1.external_references.len(), 0);
        assert_eq!(sg1.existing_groups.len(), 0);
    }

    #[test]
    fn test_merge() {
        let sg1 = SecurityGroups {
            external_references: hashmap![
                "1".to_string() => vec!["a".to_string(), "b".to_string()],
            ],
            existing_groups: vec![ExistingGroup {
                region: "1".to_string(),
                group_id: "1".to_string(),
                group_name: "1".to_string(),
                group_description: "1".to_string(),
                references: HashSet::default(),
            }],
        };
        let sg2 = SecurityGroups {
            external_references: hashmap![
                "1".to_string() => vec!["c".to_string()],
                "2".to_string() => vec!["e".to_string()]
            ],
            existing_groups: vec![ExistingGroup {
                region: "2".to_string(),
                group_id: "2".to_string(),
                group_name: "2".to_string(),
                group_description: "2".to_string(),
                references: HashSet::default(),
            }],
        };
        let mut sg = sg1.clone();
        sg.merge(&sg2);
        assert_eq!(sg.external_references.len(), 2);
        assert_eq!(
            sg.external_references,
            hashmap![
                "1".to_string() => vec!["a".to_string(), "b".to_string(), "c".to_string()],
                "2".to_string() => vec!["e".to_string()],
            ]
        );
        assert_eq!(sg.existing_groups.len(), 2);
        assert_eq!(
            sg.existing_groups,
            itertools::chain(&sg1.existing_groups, &sg2.existing_groups)
                .cloned()
                .collect_vec()
        );
    }
}
