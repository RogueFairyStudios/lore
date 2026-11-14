// SPDX-FileCopyrightText: 2026 Rogue Fairy Studios
// SPDX-License-Identifier: MIT

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context as _;
use clap::Parser;
use lore_base::lore_spawn;
use rfs_lore_bridge::BridgeRuntime;
use rfs_lore_bridge::build_combined_router;
use rfs_lore_bridge::build_public_router;
use rfs_lore_bridge::config::BridgeConfig;
use rfs_lore_bridge::grpc::GrpcBridgeService;
use rfs_lore_bridge::jwks::TokenVerifier;
use rfs_lore_bridge::signing::KeyOrigin;
use rfs_lore_bridge::signing::TokenSigner;
use rfs_lore_bridge::store::BridgeStore;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_util::task::AbortOnDropHandle;
use tracing::Instrument as _;
use tracing::info;
use tracing::warn;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "rfs-lore-bridge",
    about = "Rogue Fairy Studios authentik OIDC token-exchange and Lore project registry bridge"
)]
struct Cli {
    /// Optional path to a TOML configuration file.
    #[arg(long)]
    config: Option<PathBuf>,

    /// Print a freshly generated base64 PKCS#8 P-256 signing key (`RFS_LORE_SIGNING_KEY_B64`) and exit.
    #[arg(long)]
    generate_signing_key: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    let cli = Cli::parse();
    if cli.generate_signing_key {
        let key = TokenSigner::generate_base64_pkcs8()
            .context("generating base64 PKCS#8 P-256 signing key")?;
        println!("{key}");
        return Ok(());
    }

    let config = BridgeConfig::load(cli.config.as_deref(), |name| std::env::var(name).ok())
        .context("loading rfs-lore-bridge configuration")?;
    let bind_addr = config.bind_addr()?;
    let grpc_bind_addr = config.grpc_bind_addr()?;

    let (signer, key_origin) = TokenSigner::load_or_generate(
        config.signing_key_b64.as_deref(),
        config.signing_key_path.as_deref(),
    )
    .context("initializing ES256 signing key")?;

    if key_origin == KeyOrigin::Ephemeral {
        warn!(
            "Using an ephemeral in-memory signing key; configure signing_key_path or \
             RFS_LORE_SIGNING_KEY_B64 in production so restarts keep active tokens valid"
        );
    }
    if config.state_path.is_none() {
        warn!(
            "state_path is unset; repository registrations are held in memory only and will be \
             lost on restart"
        );
    }

    let store = BridgeStore::open_with_paths_and_field(
        config.state_path.clone(),
        config.user_state_path.clone(),
        config.authentik.user_id_field,
    )
    .context("opening repository registry state store")?;
    let verifier =
        TokenVerifier::new(config.clone(), signer.clone()).context("initializing JWT verifier")?;

    let runtime = Arc::new(BridgeRuntime::new(config, signer, verifier, store));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let _shutdown_watcher = AbortOnDropHandle::new(lore_spawn!(
        watch_os_shutdown(shutdown_tx.clone()).in_current_span()
    ));

    if let Some(grpc_addr) = grpc_bind_addr {
        let http_listener = TcpListener::bind(bind_addr)
            .await
            .with_context(|| format!("binding HTTP listener on {bind_addr}"))?;
        let grpc_listener = TcpListener::bind(grpc_addr)
            .await
            .with_context(|| format!("binding gRPC listener on {grpc_addr}"))?;

        info!(
            http_bind = %bind_addr,
            grpc_bind = %grpc_addr,
            issuer = %runtime.config.issuer,
            kid = %runtime.signer.kid(),
            ?key_origin,
            "rfs-lore-bridge listening on separate HTTP and gRPC sockets"
        );

        let http_app = build_public_router(runtime.clone());
        let grpc_app = GrpcBridgeService::new(runtime).into_axum_router();

        let mut servers = JoinSet::new();
        lore_spawn!(
            servers,
            serve_named_router("HTTP", http_listener, http_app, shutdown_rx.clone())
                .in_current_span()
        );
        lore_spawn!(
            servers,
            serve_named_router("gRPC", grpc_listener, grpc_app, shutdown_rx).in_current_span()
        );

        let mut first_error: Option<anyhow::Error> = None;
        loop {
            let Some(joined) = servers.join_next().await else {
                break;
            };
            let _ = shutdown_tx.send(true);
            match joined {
                Ok(Err(err)) if first_error.is_none() => first_error = Some(err),
                Err(join_err) if first_error.is_none() => {
                    first_error =
                        Some(anyhow::Error::new(join_err).context("server task panicked"));
                }
                Ok(Ok(()) | Err(_)) | Err(_) => {}
            }
        }
        if let Some(err) = first_error {
            return Err(err);
        }
    } else {
        let listener = TcpListener::bind(bind_addr)
            .await
            .with_context(|| format!("binding combined HTTP/gRPC listener on {bind_addr}"))?;

        info!(
            bind = %bind_addr,
            issuer = %runtime.config.issuer,
            kid = %runtime.signer.kid(),
            ?key_origin,
            "rfs-lore-bridge listening (multiplexed HTTP + gRPC)"
        );

        let app = build_combined_router(runtime);
        serve_named_router("combined", listener, app, shutdown_rx).await?;
    }

    Ok(())
}

async fn serve_named_router(
    label: &'static str,
    listener: TcpListener,
    app: axum::Router,
    shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    axum::serve(listener, app)
        .with_graceful_shutdown(wait_for_shutdown(shutdown_rx))
        .await
        .with_context(|| format!("{label} server exited with error"))
}

async fn wait_for_shutdown(mut shutdown_rx: watch::Receiver<bool>) {
    if *shutdown_rx.borrow_and_update() {
        return;
    }
    let _ = shutdown_rx.changed().await;
}

async fn watch_os_shutdown(shutdown_tx: watch::Sender<bool>) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::SignalKind;
        use tokio::signal::unix::signal;

        if let Ok(mut sigterm) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = sigterm.recv() => {}
            }
        } else {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    info!("Shutdown signal received");
    let _ = shutdown_tx.send(true);
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
}
