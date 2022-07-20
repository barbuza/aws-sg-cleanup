use aws_config::meta::region::RegionProviderChain;
use itertools::Itertools;
use log::info;

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
