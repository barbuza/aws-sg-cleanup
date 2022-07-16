use itertools::Itertools;
use log::info;

pub async fn load_regions() -> impl Iterator<Item = aws_sdk_ec2::Region> {
    info!("loading regions");
    let config = aws_config::from_env().load().await;
    let client = aws_sdk_ec2::Client::new(&config);
    let res = Vec::from(
        client
            .describe_regions()
            .send()
            .await
            .unwrap()
            .regions()
            .unwrap(),
    )
    .into_iter()
    .map(|x| aws_sdk_ec2::Region::new(x.region_name.unwrap()))
    .collect_vec()
    .into_iter();

    res
}
