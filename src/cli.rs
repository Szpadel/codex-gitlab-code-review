use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::auth_cli::{AuthAction as RunnerAuthAction, AuthRunner};
use crate::bootstrap::{BootstrapOptions, bootstrap_runtime, load_config};
use crate::demo_history::seed_example_history;
use crate::scheduler;

#[derive(Parser, Debug)]
#[command(author, version, about = "Codex GitLab review service")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    /// Run a single scan and exit.
    #[arg(long)]
    once: bool,
    /// Force dry-run mode (skip GitLab writes).
    #[arg(long)]
    dry_run: bool,
    /// Enable verbose logging and full Codex app-server event logs.
    #[arg(long)]
    debug: bool,
    /// Start with mocked GitLab and Codex integrations plus development tools UI.
    #[arg(long)]
    dev_mode: bool,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Manage Codex authentication.
    Auth(AuthCommand),
    /// Developer-only utilities.
    Dev(DevCommand),
}

#[derive(Parser, Debug)]
struct AuthCommand {
    #[command(subcommand)]
    action: AuthSubcommand,
}

#[derive(Subcommand, Debug)]
enum AuthSubcommand {
    /// Run device-code login flow and persist auth.json.
    Login,
    /// Show current authentication status.
    Status,
}

#[derive(Parser, Debug)]
struct DevCommand {
    #[command(subcommand)]
    action: DevSubcommand,
}

#[derive(Subcommand, Debug)]
enum DevSubcommand {
    /// Append synthetic review and mention history for validating the web UI.
    SeedExampleHistory {
        /// Required acknowledgement that this mutates the configured database.path.
        #[arg(long)]
        yes_append_to_configured_state: bool,
    },
}

pub async fn run() -> Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.debug);

    let config = load_config(cli.dev_mode)?;
    if let Some(command) = cli.command {
        return run_command(command, config.as_ref(), cli.debug).await;
    }

    let run_once = cli.once || env_flag("RUN_ONCE");
    let force_dry_run = cli.dry_run || env_flag("DRY_RUN");
    let runtime = bootstrap_runtime(
        config,
        BootstrapOptions {
            run_once,
            force_dry_run,
            log_all_json: cli.debug,
            dev_mode: cli.dev_mode,
        },
    )
    .await?;

    scheduler::run(runtime).await
}

async fn run_command(command: Command, config: &crate::config::Config, debug: bool) -> Result<()> {
    match command {
        Command::Auth(auth_cmd) => {
            let runner = AuthRunner::new(&config.docker, config.codex.clone())?;
            let action = match auth_cmd.action {
                AuthSubcommand::Login => RunnerAuthAction::Login,
                AuthSubcommand::Status => RunnerAuthAction::Status,
            };
            runner.run(action, debug).await
        }
        Command::Dev(dev_cmd) => run_dev_command(dev_cmd, config).await,
    }
}

async fn run_dev_command(dev_cmd: DevCommand, config: &crate::config::Config) -> Result<()> {
    match dev_cmd.action {
        DevSubcommand::SeedExampleHistory {
            yes_append_to_configured_state,
        } => {
            if !yes_append_to_configured_state {
                anyhow::bail!(
                    "refusing to append demo data into configured runtime state; rerun with --yes-append-to-configured-state"
                );
            }
            let report = seed_example_history(config).await?;
            println!(
                "Seeded {} demo run(s) into {}.",
                report.runs.len(),
                report.database_path
            );
            for run in report.runs {
                println!(
                    "- run {}: {:?} {} !{} [{}] -> {} | {}",
                    run.run_id,
                    run.kind,
                    run.repo,
                    run.iid,
                    run.result,
                    run.history_path,
                    run.mr_history_path
                );
            }
            Ok(())
        }
    }
}

fn init_tracing(debug: bool) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        if debug {
            tracing_subscriber::EnvFilter::new("debug")
        } else {
            tracing_subscriber::EnvFilter::new("info")
        }
    });
    tracing_subscriber::fmt().with_env_filter(filter).init();
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .is_ok_and(|value| matches!(value.to_lowercase().as_str(), "1" | "true" | "yes"))
}
