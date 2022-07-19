use std::collections::HashSet;

use aws_sdk_ec2::types::SdkError;
use clap::Parser;
use cli_table::{print_stdout, Cell, Style, Table};
use itertools::Itertools;
use log::{info, warn};
use rand::Rng;
use security::SecurityGroups;
use sha1::{Digest, Sha1};
use utils::{load_regional_groups, load_regions};

mod alb;
mod ec2;
mod elasticache;
mod lambda;
mod rds;
mod security;
mod utils;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    env_logger::builder()
        .filter_module("aws_config", log::LevelFilter::Warn)
        .filter_module("aws_smithy_http_tower", log::LevelFilter::Warn)
        .filter_level(log::LevelFilter::Info)
        .format_timestamp(None)
        .init();

    match args {
        Cli::Print => print_unused().await?,
        Cli::Clean => clean_unused().await?,
        Cli::MakeNoise => make_noise().await?,
    }

    Ok(())
}

#[derive(Parser)]
#[clap(name = "aws-sg-cleanup", bin_name = "aws-sg-cleanup")]
enum Cli {
    #[clap(about = "Print all security groups in all regions and services referencing them")]
    Print,
    #[clap(about = "Delete unused security groups in all regions")]
    Clean,
    #[clap(about = "Create 20 empty security groups in default region")]
    MakeNoise,
}

async fn load_groups() -> anyhow::Result<SecurityGroups> {
    let regions = load_regions().await?;

    let regional_configs = futures::future::join_all(
        regions.map(|region| aws_config::from_env().region(region.clone()).load()),
    )
    .await;

    let groups = futures::future::join_all(regional_configs.into_iter().map(load_regional_groups))
        .await
        .into_iter()
        .flatten()
        .fold(SecurityGroups::default(), |mut acc, item| {
            acc.merge(&item);
            acc
        });

    Ok(groups)
}

async fn make_noise() -> anyhow::Result<()> {
    let config = aws_config::load_from_env().await;
    let client = aws_sdk_ec2::Client::new(&config);
    for _ in 0..20 {
        let rand_string = rand::thread_rng()
            .sample_iter(rand::distributions::Standard)
            .take(64)
            .collect_vec();
        let mut hasher = Sha1::new();
        hasher.update(rand_string);
        let hash = hasher.finalize();
        let hash = base16ct::lower::encode_string(&hash);

        let name = format!("noise-{}", hash);
        info!("creating security group {}", name);
        client
            .create_security_group()
            .group_name(name.clone())
            .description(name.clone())
            .send()
            .await?;
    }
    Ok(())
}

async fn print_unused() -> anyhow::Result<()> {
    let groups = load_groups().await?;
    let rows = groups
        .existing_groups
        .iter()
        .sorted_by_key(|x| x.region.clone())
        .map(|group| {
            let group_id = group.group_id.clone();
            let refs = groups
                .collect_referencing_services(&group_id, HashSet::new())
                .iter()
                .join(", ");

            let bold = refs.is_empty();
            vec![
                group.region.clone().cell().bold(bold),
                group.group_id.clone().cell().bold(bold),
                group.group_name.clone().cell().bold(bold),
                refs.cell(),
            ]
        })
        .collect_vec();
    if !rows.is_empty() {
        let table = rows.table().title(vec![
            "Region".cell().bold(true),
            "Group ID".cell().bold(true),
            "Group Name".cell().bold(true),
            "References".cell().bold(true),
        ]);
        print_stdout(table)?;
    }
    Ok(())
}

async fn clean_unused() -> anyhow::Result<()> {
    let groups = load_groups().await?;
    for (region, unused_groups) in groups
        .find_unused()
        .into_iter()
        .group_by(|x| x.region.clone())
        .into_iter()
    {
        info!("cleaning {}", region);
        let sdk_config = aws_config::from_env()
            .region(aws_sdk_ec2::Region::new(region))
            .load()
            .await;
        let client = aws_sdk_ec2::Client::new(&sdk_config);

        for group in unused_groups {
            info!("deleting {}", group.group_id);
            match client
                .delete_security_group()
                .set_group_id(Some(group.group_id.clone()))
                .send()
                .await
            {
                Err(SdkError::ServiceError { err, .. }) => {
                    warn!("failed to delete {}: {}", group.group_id, err);
                    Ok(())
                }
                Err(err) => Err(err),
                _ => Ok(()),
            }?
        }
    }
    Ok(())
}
