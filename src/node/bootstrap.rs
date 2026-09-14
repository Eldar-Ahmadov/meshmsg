use super::common::BLOB_GC_INTERVAL;
use crate::{
    attachment,
    config::State,
    direct::{self, DIRECT_ALPN},
    gossip,
    invite::Invite,
    presence,
};
use anyhow::{Context, Result};
use iroh::{
    address_lookup::memory::MemoryLookup, endpoint::presets, protocol::Router, Endpoint, PublicKey,
    SecretKey,
};
use iroh_blobs::{
    api::{downloader::Downloader, Store},
    store::{
        fs::{options::Options as FsStoreOptions, FsStore},
        GcConfig,
    },
    BlobsProtocol,
};
use iroh_gossip::{
    api::{GossipReceiver, GossipSender},
    net::Gossip,
    proto::TopicId,
};
use std::path::Path;
use tokio::sync::mpsc;

pub(super) struct RunningNode {
    pub(super) endpoint: Endpoint,
    pub(super) router: Router,
    pub(super) sender: GossipSender,
    pub(super) receiver: GossipReceiver,
    pub(super) presence_sender: GossipSender,
    pub(super) presence_receiver: GossipReceiver,
    pub(super) secret: SecretKey,
    pub(super) bootstrap_peers: Vec<PublicKey>,
    pub(super) bootstrap_addrs: Vec<iroh::EndpointAddr>,
    pub(super) blob_store: Store,
    pub(super) downloader: Downloader,
    pub(super) lookup: MemoryLookup,
    pub(super) presence_lookup: MemoryLookup,
    pub(super) direct_replay: direct::ReplayWorker,
    pub(super) direct_incoming: mpsc::Receiver<meshmsg_protocol::Event>,
}

pub(super) async fn start(
    state: &State,
    secret: SecretKey,
    state_dir: &Path,
) -> Result<RunningNode> {
    state.validate()?;
    attachment::cleanup_stale_state_staging(state_dir)
        .context("recover stale attachment share staging")?;
    let topic: TopicId = state.topic_id()?;
    // Keep stable invite/attachment routes isolated from expiring presence.
    // Each MemoryLookup owns one source so presence cleanup cannot erase another.
    let lookup = MemoryLookup::with_provenance("meshmsg_stable");
    let presence_lookup = MemoryLookup::with_provenance("meshmsg_presence");
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret.clone())
        .address_lookup(lookup.clone())
        .address_lookup(presence_lookup.clone())
        .bind()
        .await?;
    let gossip = Gossip::builder()
        .alpn(gossip::ALPN)
        .max_message_size(gossip::MAX_MESSAGE_SIZE)
        .spawn(endpoint.clone());
    // Isolate control-plane membership from the long-standing broadcast Gossip
    // actor. Sharing one actor/connection pool across both topics can perturb
    // broadcast neighbor liveness during failover and rejoin.
    let presence_gossip = Gossip::builder()
        .alpn(presence::ALPN)
        .max_message_size(presence::MAX_GOSSIP_MESSAGE_SIZE)
        .spawn(endpoint.clone());
    let blob_root = state_dir.join("blobs-v1").join(secret.public().to_string());
    let mut blob_options = FsStoreOptions::new(&blob_root);
    blob_options.gc = Some(GcConfig {
        interval: BLOB_GC_INTERVAL,
        add_protected: None,
    });
    let fs_store = FsStore::load_with_opts(blob_root.join("blobs.db"), blob_options)
        .await
        .context("open persistent attachment store")?;
    let blob_store: Store = fs_store.into();
    let downloader = blob_store.downloader(&endpoint);
    let blobs = BlobsProtocol::new(&blob_store, None);
    let (direct, direct_replay, direct_incoming) = direct::setup(secret.clone(), topic, state_dir)
        .context("open persistent direct replay state")?;
    let router = Router::builder(endpoint.clone())
        .accept(gossip::ALPN, gossip.clone())
        .accept(presence::ALPN, presence_gossip.clone())
        .accept(iroh_blobs::ALPN, blobs)
        .accept(DIRECT_ALPN, direct)
        .spawn();
    let mut bootstrap = Vec::new();
    let mut bootstrap_addrs = Vec::new();
    if let Some(token) = &state.invite {
        let invite: Invite = token.parse()?;
        for peer in invite.bootstrap_peers {
            if peer.id != endpoint.id() {
                presence::validate_endpoint_addr(&peer, peer.id)
                    .context("invalid bootstrap endpoint address")?;
                bootstrap.push(peer.id);
                bootstrap_addrs.push(peer.clone());
                lookup.set_endpoint_info(peer);
            }
        }
    }
    let subscription = if bootstrap.is_empty() {
        gossip.subscribe(topic, vec![]).await?
    } else {
        gossip.subscribe_and_join(topic, bootstrap.clone()).await?
    };
    let (sender, receiver) = subscription.split();
    let presence_subscription = if bootstrap.is_empty() {
        presence_gossip
            .subscribe(presence::presence_topic(topic), vec![])
            .await?
    } else {
        presence_gossip
            .subscribe_and_join(presence::presence_topic(topic), bootstrap.clone())
            .await?
    };
    let (presence_sender, presence_receiver) = presence_subscription.split();
    Ok(RunningNode {
        endpoint,
        router,
        sender,
        receiver,
        presence_sender,
        presence_receiver,
        secret,
        bootstrap_peers: bootstrap,
        bootstrap_addrs,
        blob_store,
        downloader,
        lookup,
        presence_lookup,
        direct_replay,
        direct_incoming,
    })
}
