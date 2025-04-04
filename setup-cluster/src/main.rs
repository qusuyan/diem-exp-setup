use diem_crypto::Uniform;
use diem_crypto::ValidCryptoMaterial;
use diem_crypto::ed25519::Ed25519PrivateKey;
use diem_crypto::x25519::{PrivateKey, PublicKey};

use rand::{RngCore, thread_rng};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json;

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;
use std::process::Command;
use std::sync::LazyLock;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;
use std::u64;

static NOW: LazyLock<u64> = LazyLock::new(|| {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
});

static GENESIS_TOOL_PATH: LazyLock<PathBuf> = LazyLock::new(|| {
    let path = std::env::var("GENESIS_TOOL_PATH").expect("Path to diem-genesis-tool not set");
    PathBuf::from(path)
});

static MOVE_SCRIPT_PATH: LazyLock<PathBuf> = LazyLock::new(|| {
    let path = std::env::var("MOVE_SCRIPT_PATH").expect("Path to move scripts not set");
    PathBuf::from(path)
});

const SAFETY_DATA: &str = r#"
{
    "epoch": 1,
    "last_voted_round": 0,
    "preferred_round": 0,
    "one_chain_round": 0,
    "last_vote": null
}
"#;
const SUCCESS: &[u8] = b"Success!\n";
const STORAGE_FILE: &str = "storage.json";
const CONFIG_FILE: &str = "config.yaml";

#[derive(Serialize, Deserialize)]
struct Data {
    data: String,
    last_update: u64,
    value: serde_json::Value,
}

#[derive(Serialize, Deserialize)]
struct Storage(HashMap<String, Data>);

impl Storage {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn set<T: Serialize>(&mut self, key: &str, value: T) {
        self.0.insert(
            String::from(key),
            Data {
                data: String::from("GetResponse"),
                last_update: *NOW,
                value: serde_json::to_value(value).unwrap(),
            },
        );
    }

    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        self.0
            .get(key)
            .and_then(|data| serde_json::from_value(data.value.clone()).ok())
    }
}

type Key = [u8; 32];

#[derive(Deserialize, Serialize)]
struct StorageKey(#[serde(serialize_with = "to_base64", deserialize_with = "from_base64")] Key);

#[derive(Serialize, Deserialize)]
struct KeySet {
    keys: HashMap<u64, StorageKey>,
    current: u64,
}

#[derive(Deserialize, Serialize)]
struct Layout {
    pub operators: Vec<String>,
    pub owners: Vec<String>,
    pub diem_root: String,
    pub treasury_compliance: String,
}

#[derive(Deserialize, Serialize)]
struct Seed {
    addresses: Vec<String>,
    keys: Vec<String>,
    role: String,
}

fn main() {
    let validators = ["10.10.1.1", "10.10.1.2"];
    let working_dir = PathBuf::from("/users/squ27/test");
    let out_dir = PathBuf::from("./test/");

    let mut rng = thread_rng();

    std::fs::create_dir(&out_dir).expect("directory already exists");
    let out_dir = std::fs::canonicalize(out_dir).unwrap();

    // create associate keys
    let admin_key = Ed25519PrivateKey::generate(&mut rng);
    let mint_key_location = out_dir.join("mint.key");
    let serialized_key = bcs::to_bytes(&admin_key).unwrap();
    let mut file = File::create(mint_key_location).unwrap();
    file.write_all(&serialized_key).unwrap();
    file.flush().unwrap();

    let admin_key_bytes = admin_key.to_bytes();
    let mut association_storage = Storage::new();
    association_storage.set(
        "diem_root",
        Ed25519PrivateKey::try_from(admin_key_bytes.as_ref()).unwrap(),
    );
    association_storage.set(
        "treasury_compliance",
        Ed25519PrivateKey::try_from(admin_key_bytes.as_ref()).unwrap(),
    );

    let association_path = out_dir.join("association");
    std::fs::create_dir(&association_path).unwrap();
    let association_config_path = association_path.join(STORAGE_FILE);
    let file = File::create(&association_config_path).unwrap();
    let mut writer = BufWriter::new(file);
    serde_json::to_writer(&mut writer, &association_storage).unwrap();
    writer.flush().unwrap();

    // create validator network address key
    let mut validator_network_address_encryption_key = Key::default();
    rng.fill_bytes(&mut validator_network_address_encryption_key);

    for id in 0..validators.len() {
        let mut validator_storage = Storage::new();
        validator_storage.set(
            "safety_data",
            serde_json::from_str::<serde_json::Value>(SAFETY_DATA).unwrap(),
        );

        let validator_key = PrivateKey::generate(&mut rng);
        let validator_key_value = serde_json::to_value(validator_key).unwrap();
        validator_storage.set("fullnode_network", validator_key_value.clone());
        validator_storage.set("validator_network", validator_key_value.clone());
        validator_storage.set("consensus", validator_key_value.clone());
        validator_storage.set("operator", validator_key_value.clone());
        validator_storage.set("execution", validator_key_value.clone());
        validator_storage.set("owner", validator_key_value);

        let keys = HashMap::from([(
            0,
            StorageKey(validator_network_address_encryption_key.clone()),
        )]);
        let key_set = KeySet { keys, current: 0 };
        validator_storage.set("validator_network_address_keys", key_set);

        let validator_path = out_dir.join(get_dir(id));
        std::fs::create_dir(&validator_path).unwrap();
        let file = File::create(validator_path.join(STORAGE_FILE)).unwrap();
        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, &validator_storage).unwrap();
        writer.flush().unwrap();
    }

    let shared_storage_path = out_dir.join("genesis.json");

    // create layout
    let operators = (0..validators.len()).map(|id| get_operator(id)).collect();
    let owners = (0..validators.len()).map(|id| get_owner(id)).collect();
    let layout = Layout {
        operators,
        owners,
        diem_root: String::from("admin"),
        treasury_compliance: String::from("admin"),
    };

    let layout_path = out_dir.join("layout.toml");
    let layout_file = File::create(&layout_path).unwrap();
    let mut writer = BufWriter::new(layout_file);
    writer
        .write(toml::to_string(&layout).unwrap().as_bytes())
        .unwrap();
    writer.flush().unwrap();

    let output = Command::new(&*GENESIS_TOOL_PATH)
        .args([
            "set-layout",
            "--path",
            layout_path.to_str().unwrap(),
            "--shared-backend",
            &format!(
                "backend=disk;path={}",
                shared_storage_path.to_str().unwrap()
            ),
        ])
        .output()
        .expect("set-layout failed");
    if output.stdout != SUCCESS {
        print!(
            "set-layout failed: \n[stdout]\n{}\n[stderr]\n{}\n",
            String::from_utf8(output.stdout).unwrap(),
            String::from_utf8(output.stderr).unwrap()
        );
        return;
    }

    // import move modules
    let output = Command::new(&*GENESIS_TOOL_PATH)
        .args([
            "set-move-modules",
            "--dir",
            MOVE_SCRIPT_PATH.to_str().unwrap(),
            "--shared-backend",
            &format!(
                "backend=disk;path={}",
                shared_storage_path.to_str().unwrap()
            ),
        ])
        .output()
        .expect("set-move-modules failed");
    if output.stdout != SUCCESS {
        print!(
            "set-move-modules failed: \n[stdout]\n{}\n[stderr]\n{}\n",
            String::from_utf8(output.stdout).unwrap(),
            String::from_utf8(output.stderr).unwrap()
        );
        return;
    }

    // import diem-root-key
    let output = Command::new(&*GENESIS_TOOL_PATH)
        .args([
            "diem-root-key",
            "--validator-backend",
            &format!(
                "backend=disk;path={}",
                association_config_path.to_str().unwrap()
            ),
            "--shared-backend",
            &format!(
                "backend=disk;path={};namespace=admin",
                shared_storage_path.to_str().unwrap()
            ),
        ])
        .output()
        .expect("diem-root-key failed");
    if output.stdout != SUCCESS {
        print!(
            "diem-root-key failed: \n[stdout]\n{}\n[stderr]\n{}\n",
            String::from_utf8(output.stdout).unwrap(),
            String::from_utf8(output.stderr).unwrap()
        );
        return;
    }

    // import diem-treasury-compliance-key
    let output = Command::new(&*GENESIS_TOOL_PATH)
        .args([
            "treasury-compliance-key",
            "--validator-backend",
            &format!(
                "backend=disk;path={}",
                association_config_path.to_str().unwrap()
            ),
            "--shared-backend",
            &format!(
                "backend=disk;path={};namespace=admin",
                shared_storage_path.to_str().unwrap()
            ),
        ])
        .output()
        .expect("treasury-compliance-key failed");
    if output.stdout != SUCCESS {
        print!(
            "treasury-compliance-key failed: \n[stdout]\n{}\n[stderr]\n{}\n",
            String::from_utf8(output.stdout).unwrap(),
            String::from_utf8(output.stderr).unwrap()
        );
        return;
    }

    for (id, addr) in validators.iter().enumerate() {
        let validator_storage_path = out_dir.join(get_dir(id)).join(STORAGE_FILE);

        // import owner-key
        let output = Command::new(&*GENESIS_TOOL_PATH)
            .args([
                "owner-key",
                "--validator-backend",
                &format!(
                    "backend=disk;path={}",
                    validator_storage_path.to_str().unwrap()
                ),
                "--shared-backend",
                &format!(
                    "backend=disk;path={};namespace={}",
                    shared_storage_path.to_str().unwrap(),
                    get_owner(id)
                ),
            ])
            .output()
            .expect("owner-key failed");
        if output.stdout != SUCCESS {
            print!(
                "owner-key failed for validator {}: \n[stdout]\n{}\n[stderr]\n{}\n",
                id,
                String::from_utf8(output.stdout).unwrap(),
                String::from_utf8(output.stderr).unwrap()
            );
            return;
        }

        // import operator-key
        let output = Command::new(&*GENESIS_TOOL_PATH)
            .args([
                "operator-key",
                "--validator-backend",
                &format!(
                    "backend=disk;path={}",
                    validator_storage_path.to_str().unwrap()
                ),
                "--shared-backend",
                &format!(
                    "backend=disk;path={};namespace={}",
                    shared_storage_path.to_str().unwrap(),
                    get_operator(id)
                ),
            ])
            .output()
            .expect("operator-key failed");
        if output.stdout != SUCCESS {
            print!(
                "operator-key failed for validator {}: \n[stdout]\n{}\n[stderr]\n{}\n",
                id,
                String::from_utf8(output.stdout).unwrap(),
                String::from_utf8(output.stderr).unwrap()
            );
            return;
        }

        // set-operator
        let output = Command::new(&*GENESIS_TOOL_PATH)
            .args([
                "set-operator",
                "--shared-backend",
                &format!(
                    "backend=disk;path={};namespace={}",
                    shared_storage_path.to_str().unwrap(),
                    get_owner(id)
                ),
                "--operator-name",
                &get_operator(id),
            ])
            .output()
            .expect("operator-key failed");
        if output.stdout != SUCCESS {
            print!(
                "operator-key failed for validator {}: \n[stdout]\n{}\n[stderr]\n{}\n",
                id,
                String::from_utf8(output.stdout).unwrap(),
                String::from_utf8(output.stderr).unwrap()
            );
            return;
        }

        // validator-config
        let output = Command::new(&*GENESIS_TOOL_PATH)
            .args([
                "validator-config",
                "--chain-id",
                "TESTING",
                "--owner-name",
                &get_owner(id),
                "--validator-backend",
                &format!(
                    "backend=disk;path={}",
                    validator_storage_path.to_str().unwrap()
                ),
                "--shared-backend",
                &format!(
                    "backend=disk;path={};namespace={}",
                    shared_storage_path.to_str().unwrap(),
                    get_operator(id)
                ),
                "--validator-address",
                &get_validator_addr(addr),
                "--fullnode-address",
                &get_fullnode_addr(addr),
            ])
            .output()
            .expect("validator-config failed");
        if output.stdout != SUCCESS {
            print!(
                "validator-config failed for validator {}: \n[stdout]\n{}\n[stderr]\n{}\n",
                id,
                String::from_utf8(output.stdout).unwrap(),
                String::from_utf8(output.stderr).unwrap()
            );
            return;
        }
    }

    // create genesis blob
    let genesis_path = out_dir.join("genesis.blob");
    let output = Command::new(&*GENESIS_TOOL_PATH)
        .args([
            "genesis",
            "--chain-id",
            "TESTING",
            "--shared-backend",
            &format!(
                "backend=disk;path={}",
                shared_storage_path.to_str().unwrap(),
            ),
            "--path",
            &genesis_path.to_str().unwrap(),
        ])
        .output()
        .expect("genesis failed");
    if output.stdout != SUCCESS {
        print!(
            "genesis failed: \n[stdout]\n{}\n[stderr]\n{}\n",
            String::from_utf8(output.stdout).unwrap(),
            String::from_utf8(output.stderr).unwrap()
        );
        return;
    }

    // create waypoint
    let output = Command::new(&*GENESIS_TOOL_PATH)
        .args([
            "create-waypoint",
            "--chain-id",
            "TESTING",
            "--shared-backend",
            &format!(
                "backend=disk;path={}",
                shared_storage_path.to_str().unwrap(),
            ),
        ])
        .output()
        .expect("create-waypoint failed");
    let stdout = String::from_utf8(output.stdout).unwrap();
    if !stdout.starts_with("Waypoint: ") {
        print!(
            "create-waypoint failed: \n[stdout]\n{}\n[stderr]\n{}\n",
            stdout,
            String::from_utf8(output.stderr).unwrap()
        );
        return;
    }

    let waypoint = stdout[10..].trim();

    // insert waypoint
    for id in 0..validators.len() {
        let validator_storage_path = out_dir.join(get_dir(id)).join(STORAGE_FILE);
        let output = Command::new(&*GENESIS_TOOL_PATH)
            .args([
                "insert-waypoint",
                "--validator-backend",
                &format!(
                    "backend=disk;path={}",
                    validator_storage_path.to_str().unwrap(),
                ),
                "--waypoint",
                &waypoint,
            ])
            .output()
            .expect("insert-waypoint failed");
        if output.stdout != SUCCESS {
            print!(
                "insert-waypoint: \n[stdout]\n{}\n[stderr]\n{}\n",
                String::from_utf8(output.stdout).unwrap(),
                String::from_utf8(output.stderr).unwrap()
            );
            return;
        }
    }

    // creating config files
    // first create a map from owner account to address
    let mut validator_network = HashMap::new();
    for (id, addr) in validators.iter().enumerate() {
        let storage_path = out_dir.join(get_dir(id)).join(STORAGE_FILE);
        let file = File::open(storage_path).unwrap();
        let reader = BufReader::new(file);
        let data: Storage = serde_json::from_reader(reader).unwrap();
        let account: String = data.get("owner_account").unwrap();
        let validator_sk: PrivateKey = data.get("validator_network").unwrap();
        let validator_pk = PublicKey::from(&validator_sk);
        validator_network.insert(id, (account, *addr, validator_pk, validator_sk.to_bytes()));
    }

    for id in 0..validators.len() {
        let config_path = out_dir.join(get_dir(id)).join(CONFIG_FILE);
        let config = build_config(id, &working_dir, waypoint, validator_network.clone());
        let file = File::create(config_path).unwrap();
        let mut writer = BufWriter::new(file);
        serde_yaml::to_writer(&mut writer, &config).unwrap();
        writer.flush().unwrap();
    }
}

#[inline]
pub fn get_dir(validatr_id: usize) -> String {
    format!("validator_{}", validatr_id)
}

#[inline]
pub fn get_operator(validatr_id: usize) -> String {
    format!("op{}", validatr_id)
}

#[inline]
pub fn get_owner(validatr_id: usize) -> String {
    format!("ow{}", validatr_id)
}

#[inline]
pub fn get_validator_addr(addr: &str) -> String {
    format!("/ip4/{}/tcp/6180", addr)
}

#[inline]
pub fn get_fullnode_addr(addr: &str) -> String {
    format!("/ip4/{}/tcp/6181", addr)
}

pub fn to_base64<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&base64::encode(bytes))
}

pub fn from_base64<'de, D>(deserializer: D) -> Result<Key, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = serde::Deserialize::deserialize(deserializer)?;
    base64::decode(s)
        .map_err(serde::de::Error::custom)
        .and_then(|v| {
            std::convert::TryInto::try_into(v.as_slice()).map_err(serde::de::Error::custom)
        })
}

fn build_config(
    validator_id: usize,
    working_dir: &PathBuf,
    waypoint: &str,
    mut validator_network: HashMap<usize, (String, &str, PublicKey, Vec<u8>)>,
) -> serde_yaml::Value {
    let mut backend = serde_yaml::Mapping::new();
    backend.insert(
        serde_yaml::to_value("type").unwrap(),
        serde_yaml::to_value("on_disk_storage").unwrap(),
    );
    backend.insert(
        serde_yaml::to_value("path").unwrap(),
        serde_yaml::to_value(working_dir.join("storage.json").to_str().unwrap()).unwrap(),
    );

    let mut base = serde_yaml::Mapping::new();
    base.insert(
        serde_yaml::to_value("data_dir").unwrap(),
        serde_yaml::to_value(working_dir.join("data").to_str().unwrap()).unwrap(),
    );
    base.insert(
        serde_yaml::to_value("role").unwrap(),
        serde_yaml::to_value("validator").unwrap(),
    );
    base.insert(
        serde_yaml::to_value("waypoint").unwrap(),
        serde_yaml::to_value(HashMap::from([("from_config", waypoint)])).unwrap(),
    );

    let mut consensus = serde_yaml::Mapping::new();
    consensus.insert(
        serde_yaml::to_value("round_initial_timeout_ms").unwrap(),
        serde_yaml::to_value(20000).unwrap(),
    );
    consensus.insert(
        serde_yaml::to_value("mempool_poll_count").unwrap(),
        serde_yaml::to_value(333).unwrap(),
    );
    consensus.insert(
        serde_yaml::to_value("safety_rules").unwrap(),
        serde_yaml::to_value(HashMap::from([("backend", backend.clone())])).unwrap(),
    );

    let mut execution = serde_yaml::Mapping::new();
    execution.insert(
        serde_yaml::to_value("genesis_file_location").unwrap(),
        serde_yaml::to_value(working_dir.join("genesis.blob").to_str().unwrap()).unwrap(),
    );
    execution.insert(
        serde_yaml::to_value("backend").unwrap(),
        serde_yaml::Value::Mapping(backend.clone()),
    );

    let mut mempool = serde_yaml::Mapping::new();
    mempool.insert(
        serde_yaml::to_value("capacity_per_user").unwrap(),
        serde_yaml::to_value(u64::MAX).unwrap(),
    );

    let (account, addr, _, sk) = validator_network.remove(&validator_id).unwrap();
    let sk = Ed25519PrivateKey::try_from(sk.as_ref()).unwrap();
    let mut identity = serde_yaml::Mapping::new();
    identity.insert(
        serde_yaml::to_value("type").unwrap(),
        serde_yaml::to_value("from_config").unwrap(),
    );
    identity.insert(
        serde_yaml::to_value("key").unwrap(),
        serde_yaml::to_value(sk).unwrap(),
    );
    identity.insert(
        serde_yaml::to_value("peer_id").unwrap(),
        serde_yaml::to_value(account).unwrap(),
    );

    let seeded_network = validator_network
        .into_iter()
        .map(|(_, (account, addr, pk, _))| {
            (
                account,
                Seed {
                    addresses: vec![format!(
                        "{}/ln-noise-ik/{}/ln-handshake/0",
                        get_validator_addr(addr),
                        pk.to_string()
                    )],
                    keys: vec![pk.to_string()],
                    role: String::from("Validator"),
                },
            )
        })
        .collect::<HashMap<_, _>>();

    let mut validator_network = serde_yaml::Mapping::new();
    validator_network.insert(
        serde_yaml::to_value("discovery_method").unwrap(),
        serde_yaml::to_value("none").unwrap(),
    );
    validator_network.insert(
        serde_yaml::to_value("listen_address").unwrap(),
        serde_yaml::to_value(get_validator_addr(addr)).unwrap(),
    );
    validator_network.insert(
        serde_yaml::to_value("network_id").unwrap(),
        serde_yaml::to_value("validator").unwrap(),
    );
    validator_network.insert(
        serde_yaml::to_value("identity").unwrap(),
        serde_yaml::Value::Mapping(identity.clone()),
    );
    validator_network.insert(
        serde_yaml::to_value("seeds").unwrap(),
        serde_yaml::to_value(seeded_network).unwrap(),
    );

    let mut full_node_network = serde_yaml::Mapping::new();
    full_node_network.insert(
        serde_yaml::to_value("discovery_method").unwrap(),
        serde_yaml::to_value("none").unwrap(),
    );
    full_node_network.insert(
        serde_yaml::to_value("listen_address").unwrap(),
        serde_yaml::to_value(get_fullnode_addr(addr)).unwrap(),
    );
    full_node_network.insert(
        serde_yaml::to_value("network_id").unwrap(),
        serde_yaml::to_value(HashMap::from([("private", "vfn")])).unwrap(),
    );
    full_node_network.insert(
        serde_yaml::to_value("identity").unwrap(),
        serde_yaml::Value::Mapping(identity),
    );

    let mut json_rpc = serde_yaml::Mapping::new();
    json_rpc.insert(
        serde_yaml::to_value("address").unwrap(),
        serde_yaml::to_value("0.0.0.0:8080").unwrap(),
    );

    let mut config = serde_yaml::Mapping::new();
    config.insert(
        serde_yaml::to_value("base").unwrap(),
        serde_yaml::Value::Mapping(base),
    );
    config.insert(
        serde_yaml::to_value("consensus").unwrap(),
        serde_yaml::Value::Mapping(consensus),
    );
    config.insert(
        serde_yaml::to_value("execution").unwrap(),
        serde_yaml::Value::Mapping(execution),
    );
    config.insert(
        serde_yaml::to_value("mempool").unwrap(),
        serde_yaml::Value::Mapping(mempool),
    );
    config.insert(
        serde_yaml::to_value("validator_network").unwrap(),
        serde_yaml::Value::Mapping(validator_network),
    );
    config.insert(
        serde_yaml::to_value("full_node_networks").unwrap(),
        serde_yaml::to_value([full_node_network]).unwrap(),
    );
    config.insert(
        serde_yaml::to_value("json_rpc").unwrap(),
        serde_yaml::Value::Mapping(json_rpc),
    );

    serde_yaml::Value::Mapping(config)
}

#[cfg(test)]
mod test {
    use std::path::PathBuf;

    use diem_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
    use diem_crypto::x25519::PrivateKey;

    use serde_json;

    use crate::Storage;
    #[test]
    fn test_pk_sk_corect() {
        let pk_str = "\"d2a7de65f5cc93c83e03f7248bce5cfdea911e1b97a8dc7702a8dd2d3bea341b\"";
        let sk_str = "\"00374e47f701a368a81741fdbd14b9fc0cea83411a88b17f75d809469b9f9066\"";

        let sk: PrivateKey = serde_json::from_str(&sk_str).unwrap();
        let pk = sk.public_key();

        print!("{}", serde_json::to_string(&pk).unwrap());
        assert!(serde_json::to_string(&pk).unwrap() == pk_str);
    }

    #[test]
    fn crypto_test() {
        let mint_key_location = PathBuf::from("/users/squ27/diem-exp-setup/test/mint.key");
        let serialized = std::fs::read(mint_key_location).unwrap();
        let sk1: Ed25519PrivateKey = bcs::from_bytes(&serialized).unwrap();

        let storage_location =
            PathBuf::from("/users/squ27/diem-exp-setup/test/association/storage.json");
        let storage_file = std::fs::File::open(storage_location).unwrap();
        let storage: Storage = serde_json::from_reader(storage_file).unwrap();
        let sk2: Ed25519PrivateKey = storage.get("diem_root").unwrap();

        assert!(sk1 == sk2);

        let shared_storage_location =
            PathBuf::from("/users/squ27/diem-exp-setup/test/genesis.json");
        let shared_storage_file = std::fs::File::open(shared_storage_location).unwrap();
        let shared_storage: Storage = serde_json::from_reader(shared_storage_file).unwrap();
        let pk: Ed25519PublicKey = shared_storage.get("admin/diem_root").unwrap();

        assert!(Ed25519PublicKey::from(&sk1) == pk);
    }
}
