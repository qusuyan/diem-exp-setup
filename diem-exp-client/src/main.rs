use diem_client::Client;
use diem_client::views::VMStatusView;
use diem_crypto::Uniform;
use diem_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use diem_sdk::transaction_builder::{Currency, TransactionFactory};
use diem_sdk::types::LocalAccount;
use diem_types::account_config::addresses;
use diem_types::chain_id::ChainId;

use diem_types::transaction::authenticator::AuthenticationKey;
use rand::thread_rng;
use std::path::PathBuf;
use tokio;

#[tokio::main]
async fn main() {
    let mint_key_location = PathBuf::from("/users/squ27/diem-exp-setup/test/mint.key");
    let validator_url = "http://127.0.0.1:8080";

    let serialized_key = std::fs::read(mint_key_location).unwrap();

    let client = Client::new(validator_url);
    let transaction_factory =
        TransactionFactory::new(ChainId::test()).with_transaction_expiration_time(30);

    let treasury_account_addr = addresses::treasury_compliance_account_address();
    let treasury_account_view = client
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
    let dealer_account_view = client
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

    let mut rng = thread_rng();

    // create account 1
    let test_account_key1_raw = Ed25519PrivateKey::generate(&mut rng);
    let test_account_key1 =
        AuthenticationKey::ed25519(&Ed25519PublicKey::from(&test_account_key1_raw));
    let create_account_txn1 = {
        let builder = transaction_factory.create_parent_vasp_account(
            Currency::XUS,
            0,
            test_account_key1,
            &format!("No. {}", 0),
            false,
        );

        treasury_account.sign_with_transaction_builder(builder)
    };
    client.submit(&create_account_txn1).await.unwrap();

    let mut account1 = LocalAccount::new(
        test_account_key1.derived_address(),
        test_account_key1_raw,
        0,
    );

    // create account 2
    let test_account_key2_raw = Ed25519PrivateKey::generate(&mut rng);
    let test_account_key2 =
        AuthenticationKey::ed25519(&Ed25519PublicKey::from(&test_account_key2_raw));
    let create_account_txn2 = {
        let builder = transaction_factory.create_parent_vasp_account(
            Currency::XUS,
            0,
            test_account_key2,
            &format!("No. {}", 0),
            false,
        );

        treasury_account.sign_with_transaction_builder(builder)
    };
    client.submit(&create_account_txn2).await.unwrap();

    let account2 = LocalAccount::new(
        test_account_key2.derived_address(),
        test_account_key2_raw,
        0,
    );

    // wait for account creation to finish
    let account_creation1_result = client
        .wait_for_signed_transaction(&create_account_txn1, None, None)
        .await
        .unwrap()
        .into_inner();
    assert!(account_creation1_result.vm_status == VMStatusView::Executed);
    let account_creation2_result = client
        .wait_for_signed_transaction(&create_account_txn2, None, None)
        .await
        .unwrap()
        .into_inner();
    assert!(account_creation2_result.vm_status == VMStatusView::Executed);

    // add balance to account 1
    let add_balance_txn1 = {
        let builder = transaction_factory.peer_to_peer(Currency::XUS, account1.address(), 10);
        dealer_account.sign_with_transaction_builder(builder)
    };
    client.submit(&add_balance_txn1).await.unwrap();

    // add balance to account 2
    let add_balance_txn2 = {
        let builder = transaction_factory.peer_to_peer(Currency::XUS, account2.address(), 10);
        dealer_account.sign_with_transaction_builder(builder)
    };
    client.submit(&add_balance_txn2).await.unwrap();

    // wait for add balance to finish
    let add_balance1_result = client
        .wait_for_signed_transaction(&add_balance_txn1, None, None)
        .await
        .unwrap()
        .into_inner();
    assert!(add_balance1_result.vm_status == VMStatusView::Executed);
    let add_balance2_result = client
        .wait_for_signed_transaction(&add_balance_txn2, None, None)
        .await
        .unwrap()
        .into_inner();
    assert!(add_balance2_result.vm_status == VMStatusView::Executed);

    // check balances
    let account1_balance = client
        .get_account(account1.address())
        .await
        .unwrap()
        .into_inner()
        .unwrap()
        .balances;

    let account2_balance = client
        .get_account(account2.address())
        .await
        .unwrap()
        .into_inner()
        .unwrap()
        .balances;

    println!(
        "After setup: account 1: {:?}; account 2: {:?};",
        account1_balance, account2_balance
    );

    // account 1 transfer 5 to account 2
    let transfer_txn = {
        let builder = transaction_factory.peer_to_peer(Currency::XUS, account2.address(), 5);
        account1.sign_with_transaction_builder(builder)
    };
    client.submit(&transfer_txn).await.unwrap();

    // wait for balance transfer to finish
    let transfer_result = client
        .wait_for_signed_transaction(&transfer_txn, None, None)
        .await
        .unwrap()
        .into_inner();
    assert!(transfer_result.vm_status == VMStatusView::Executed);

    // check balances again
    let account1_balance = client
        .get_account(account1.address())
        .await
        .unwrap()
        .into_inner()
        .unwrap()
        .balances;

    let account2_balance = client
        .get_account(account2.address())
        .await
        .unwrap()
        .into_inner()
        .unwrap()
        .balances;

    println!(
        "After setup: account 1: {:?}; account 2: {:?};",
        account1_balance, account2_balance
    );
}
