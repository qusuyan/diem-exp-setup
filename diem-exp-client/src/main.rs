use diem_client::AccountAddress;
use diem_client::Client;
use diem_client::views::VMStatusView;
use diem_crypto::ed25519::Ed25519PrivateKey;
use diem_sdk::transaction_builder::{Currency, TransactionBuilder, TransactionFactory};
use diem_sdk::types::LocalAccount;
use diem_types::account_config::addresses;
use diem_types::chain_id::ChainId;

use rand::seq::SliceRandom;
use rand::thread_rng;

use std::fmt::Display;
use std::path::PathBuf;
use std::sync::Arc;

use tokio;
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant};

use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct CliArg {
    /// Path to mint.key
    #[arg(short = 'p', long)]
    mint_key: String,

    /// List of validator addresses
    #[arg(short, long)]
    validators: String,

    /// number of accounts
    #[arg(short = 'a', long)]
    num_accounts: usize,

    /// frequency at which transactions are sent, in txn/sec
    #[arg(short = 'f', long)]
    frequency: usize,

    /// number of threads
    #[arg(short = 't', long)]
    num_threads: usize,

    #[arg(short = 'e', long)]
    exp_time: u64,
}

fn main() {
    let args = CliArg::parse();

    env_logger::init();

    let mint_key_location = PathBuf::from(args.mint_key);
    let validators = std::fs::read_to_string(args.validators).unwrap();
    let validator_urls = validators
        .trim()
        .split('\n')
        .map(|addr| {
            let addr = addr.trim();
            if !addr.starts_with("http://") {
                String::from("http://") + addr
            } else {
                addr.to_string()
            }
        })
        .collect::<Vec<_>>();
    log::info!("URLS: {:?}", validator_urls);

    let serialized_key = std::fs::read(mint_key_location).unwrap();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(args.num_threads)
        .build()
        .expect("Creating runtime failed");

    let clients = validator_urls
        .into_iter()
        .map(|url| Arc::new(Client::new(url)))
        .collect::<Vec<_>>();
    assert!(clients.len() > 0);

    let accounts_per_node = args.num_accounts / clients.len();

    let transaction_factory =
        TransactionFactory::new(ChainId::test()).with_transaction_expiration_time(3600);

    rt.block_on(async {
        let treasury_account_addr = addresses::treasury_compliance_account_address();
        let treasury_account_view = clients[0]
            .get_account(treasury_account_addr)
            .await
            .unwrap()
            .into_inner()
            .unwrap();
        let mut treasury_account = LocalAccount::new(
            treasury_account_addr,
            bcs::from_bytes::<Ed25519PrivateKey>(&serialized_key).unwrap(),
            treasury_account_view.sequence_number,
        );

        let dealer_account_addr = addresses::testnet_dd_account_address();
        let dealer_account_view = clients[0]
            .get_account(dealer_account_addr)
            .await
            .unwrap()
            .into_inner()
            .unwrap();
        let mut dealer_account = LocalAccount::new(
            dealer_account_addr,
            bcs::from_bytes::<Ed25519PrivateKey>(&serialized_key).unwrap(),
            dealer_account_view.sequence_number,
        );

        // start creating accounts
        log::info!("creating accounts");
        let mut accounts: Vec<(
            Arc<Client>,
            Vec<(Arc<Mutex<LocalAccount>>, u64, AccountAddress)>,
        )> = vec![];
        let mut create_account_txns = vec![];
        for client in clients.iter() {
            let mut local_accounts = vec![];
            let mut local_create_account_txns = vec![];
            for _ in 0..accounts_per_node {
                let account = {
                    let mut rng = thread_rng();
                    LocalAccount::generate(&mut rng)
                };

                let create_account_txn = {
                    let builder = transaction_factory.create_parent_vasp_account(
                        Currency::XUS,
                        0,
                        account.authentication_key(),
                        &format!("No. {}", 0),
                        false,
                    );

                    treasury_account.sign_with_transaction_builder(builder)
                };
                client.submit(&create_account_txn).await.unwrap();

                let account_addr = account.address();
                local_accounts.push((Arc::new(Mutex::new(account)), 0u64, account_addr));
                local_create_account_txns.push(create_account_txn);
            }

            accounts.push((client.clone(), local_accounts));
            create_account_txns.push((client.clone(), local_create_account_txns));
        }

        for (client_ref, txns) in create_account_txns {
            for txn in txns {
                let result = client_ref
                    .wait_for_signed_transaction(&txn, None, None)
                    .await
                    .unwrap()
                    .into_inner();
                assert!(result.vm_status == VMStatusView::Executed);
            }
        }

        // add balances
        log::info!("adding balances");
        let mut add_balance_txns = vec![];
        for (client, local_accounts) in accounts.iter_mut() {
            let mut local_add_balance_txns = vec![];
            for (_, balance, address) in local_accounts.iter_mut() {
                let add_balance_txn = {
                    let builder = transaction_factory.peer_to_peer(Currency::XUS, *address, 1000);
                    dealer_account.sign_with_transaction_builder(builder)
                };
                *balance += 1000;
                client.submit(&add_balance_txn).await.unwrap();
                local_add_balance_txns.push(add_balance_txn);
            }
            add_balance_txns.push((client.clone(), local_add_balance_txns));
        }

        for (client_ref, txns) in add_balance_txns {
            for txn in txns {
                let result = client_ref
                    .wait_for_signed_transaction(&txn, None, None)
                    .await
                    .unwrap()
                    .into_inner();
                assert!(result.vm_status == VMStatusView::Executed);
            }
        }

        // start send txns
        log::info!("start generating transactions");
        let exp_end_time = Instant::now() + Duration::from_secs(args.exp_time);
        let mut txns_sent = 0usize;
        let mut next_send_period = Instant::now();
        let mut report_time = Instant::now();
        let mut report_counter = 0;
        loop {
            tokio::time::sleep_until(next_send_period).await;
            let mut send_handles = vec![];
            for _ in 0..args.frequency / 2 {
                let (client, sender, txn) = sample_txn(&mut accounts, &transaction_factory);
                let handle = tokio::task::spawn(send_txn(client, sender, txn));
                send_handles.push(handle);
            }

            for handle in send_handles {
                if let Err(e) = handle.await.unwrap() {
                    log::error!("Error sending transactions: {}", e)
                } else {
                    txns_sent += 1;
                }
            }

            next_send_period += Duration::from_millis(500);
            if Instant::now() >= report_time {
                log::info!("{} min passed: {} txns sent", report_counter, txns_sent);
                report_counter += 1;
                report_time += Duration::from_secs(60);
            }
            if Instant::now() >= exp_end_time {
                break;
            }
        }

        // check txns complete
        let mut handles = vec![];
        for (client, local_accounts) in accounts {
            for (account, _, _) in local_accounts {
                let handle = tokio::task::spawn(get_result(client.clone(), account));
                handles.push(handle);
            }
        }

        let mut txns_completed = 0usize;
        for handle in handles {
            match handle.await.unwrap() {
                Ok(count) => txns_completed += count,
                Err(e) => log::error!("Error looking up transaction status: {}", e),
            }
        }

        println!("Finished");
        println!(
            "Sent {} transactions in total. Committed {} transactions in {} seconds. ",
            txns_sent, txns_completed, args.exp_time
        );
        println!(
            "Throughput is {}",
            txns_completed as f64 / args.exp_time as f64
        )
    });
}

fn sample_txn(
    accounts: &mut Vec<(
        Arc<Client>,
        Vec<(Arc<Mutex<LocalAccount>>, u64, AccountAddress)>,
    )>,
    txn_factory: &TransactionFactory,
) -> (Arc<Client>, Arc<Mutex<LocalAccount>>, TransactionBuilder) {
    let mut rng = thread_rng();
    let (client, local_accounts) = accounts.choose_mut(&mut rng).unwrap();

    let (sender, sender_addr) = loop {
        let (account, balance, addr) = local_accounts.choose_mut(&mut rng).unwrap();
        if *balance > 0 {
            *balance -= 1;
            break (account.clone(), *addr);
        }
    };

    let recver = loop {
        let (_, balance, addr) = local_accounts.choose_mut(&mut rng).unwrap();
        if *addr != sender_addr {
            *balance += 1;
            break addr;
        }
    };

    let txn = txn_factory.peer_to_peer(Currency::XUS, *recver, 1);
    (client.clone(), sender, txn)
}

async fn send_txn(
    client: Arc<Client>,
    sender: Arc<Mutex<LocalAccount>>,
    txn: TransactionBuilder,
) -> Result<(), Error> {
    let signed_txn = sender.lock().await.sign_with_transaction_builder(txn);
    client.submit(&signed_txn).await?;
    Ok(())
}

async fn get_result(
    client: Arc<Client>,
    account: Arc<Mutex<LocalAccount>>,
) -> Result<usize, Error> {
    let guard = account.lock().await;
    let resp = client
        .get_account_transactions(guard.address(), 0, guard.sequence_number(), false)
        .await?
        .into_inner();
    Ok(resp
        .into_iter()
        .filter(|txn_view| txn_view.vm_status == VMStatusView::Executed)
        .count())
}

struct Error(String);

impl From<diem_client::Error> for Error {
    fn from(value: diem_client::Error) -> Self {
        Self(value.to_string())
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
