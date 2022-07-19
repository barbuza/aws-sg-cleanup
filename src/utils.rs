use aws_config::meta::region::RegionProviderChain;
use aws_types::SdkConfig;
use itertools::Itertools;
use log::info;

use crate::{
    alb, ec2, elasticache, lambda, rds,
    security::{self, SecurityGroups, SecurityGroupsProvider},
};

pub async fn load_regions() -> anyhow::Result<impl Iterator<Item = aws_sdk_ec2::Region>> {
    info!("loading regions");
    let config = aws_config::from_env()
        .region(RegionProviderChain::default_provider())
        .load()
        .await;
    let client = aws_sdk_ec2::Client::new(&config);
    let response = client.describe_regions().send().await?;

    let res = Vec::from(response.regions().unwrap())
        .into_iter()
        .map(|x| aws_sdk_ec2::Region::new(x.region_name.unwrap()))
        .collect_vec()
        .into_iter();

    Ok(res)
}

pub async fn load_regional_groups(sdk_config: SdkConfig) -> Vec<SecurityGroups> {
    let res = futures::future::join_all(vec![
        ec2::EC2Groups::new(&sdk_config).load(),
        alb::ALBGroups::new(&sdk_config).load(),
        elasticache::ElasticacheGroups::new(&sdk_config).load(),
        lambda::LambdaGroups::new(&sdk_config).load(),
        rds::RDSGroups::new(&sdk_config).load(),
        security::AWSSecurityGroups::new(&sdk_config).load(),
    ])
    .await;
    info!("{} loaded", sdk_config.region().unwrap());
    res
}
