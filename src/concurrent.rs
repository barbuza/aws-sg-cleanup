use std::{pin::Pin, sync::Arc};

use aws_types::SdkConfig;
use futures::{stream::FuturesOrdered, FutureExt, StreamExt};
use log::info;
use parking_lot::RwLock;

use crate::security::{ExistingGroup, GroupReference, KnownSecurityGroups, SecurityGroups};

#[derive(Default)]
pub struct ConcurrentLoader {
    tasks: FuturesOrdered<Pin<Box<dyn core::future::Future<Output = LoadedData>>>>,
    counter: Arc<RwLock<usize>>,
    results: Vec<LoadedData>,
    expected_results: usize,
}

impl ConcurrentLoader {
    pub async fn spawn_group_loader<T>(&mut self, sdk_config: SdkConfig)
    where
        T: KnownSecurityGroups + 'static,
    {
        let region_name = sdk_config.region().unwrap().to_string();
        info!("scanning {}@{}", T::source_name(), region_name);

        let sdk_config = sdk_config.clone();
        let source = format!("{}@{}", T::source_name(), region_name);
        self.spawn_concurrently(
            async move {
                let loader = T::from_config(sdk_config);
                LoadedData::References(
                    loader
                        .load_security_groups()
                        .await
                        .into_iter()
                        .map(|group_id| GroupReference {
                            group_id,
                            source: source.clone(),
                        })
                        .collect(),
                )
            }
            .boxed_local(),
        )
        .await;
    }

    pub async fn spawn_concurrently(
        &mut self,
        f: Pin<Box<dyn core::future::Future<Output = LoadedData>>>,
    ) {
        if *self.counter.read() >= 8 {
            self.results.push(self.tasks.next().await.unwrap());
        }

        let counter = self.counter.clone();
        *counter.write() += 1;
        self.expected_results += 1;

        self.tasks.push(Box::pin(async move {
            let result = f.await;
            *counter.write() -= 1;
            result
        }));
    }

    pub async fn collect(self) -> SecurityGroups {
        let mut items_count = 0;
        let res = itertools::chain(self.results, self.tasks.collect::<Vec<_>>().await);

        let groups = res.fold(SecurityGroups::default(), |mut groups, item| {
            items_count += 1;
            match item {
                LoadedData::References(references) => {
                    references.into_iter().for_each(|g| {
                        groups
                            .external_references
                            .entry(g.group_id)
                            .or_insert(vec![])
                            .push(g.source);
                    });
                }
                LoadedData::ExistingGroups(existing) => {
                    groups.existing_groups.extend(existing);
                }
            };
            groups
        });
        assert_eq!(items_count, self.expected_results);
        assert_eq!(*self.counter.read(), 0);
        groups
    }
}

#[derive(Debug)]
pub enum LoadedData {
    References(Vec<GroupReference>),
    ExistingGroups(Vec<ExistingGroup>),
}
