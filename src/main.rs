use aws_nitro_enclaves_attestation::NitroAdDoc;
use futures_util::TryStreamExt;
use ipfs_api::{Error::Api, IpfsApi, IpfsClient, TryFromUri};
use rs_merkle::MerkleTree;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Cursor;
#[derive(Debug, Serialize, Deserialize)]

struct PayloadData {
    pcrs: HashMap<u8, ByteBuf>,
    user_data: Option<ByteBuf>,
}
#[tokio::main]

async fn main() {
    let endpoint = "http://127.0.0.1:5001".to_string();

    let client = IpfsClient::from_str(&endpoint).unwrap();

    client.files_mkdir("/state", false).await;
    client.files_mkdir("/state/confirmed", false).await;

    match client.files_ls(Some("/input/attestations")).await {
        Ok(_) => {}
        Err(e) => match e {
            Api(api) => {
                if api.message == "file does not exist".to_string() && api.code == 0 {
                    std::process::exit(0);
                }
            }
            _ => {}
        },
    }

    match client.files_ls(Some("/input/timestamps")).await {
        Ok(_) => {}
        Err(e) => match e {
            Api(api) => {
                if api.message == "file does not exist".to_string() && api.code == 0 {
                    std::process::exit(0);
                }
            }
            _ => {}
        },
    }

    for file in client
        .files_ls(Some("/input/attestations"))
        .await
        .unwrap()
        .entries
    {
        let attestation_doc = client
            .files_read(&("/input/attestations/".to_string() + &file.name))
            .map_ok(|chunk| chunk.to_vec())
            .try_concat()
            .await
            .unwrap();

        let root_cert = &[
            48, 130, 2, 17, 48, 130, 1, 150, 160, 3, 2, 1, 2, 2, 17, 0, 249, 49, 117, 104, 27, 144,
            175, 225, 29, 70, 204, 180, 228, 231, 248, 86, 48, 10, 6, 8, 42, 134, 72, 206, 61, 4,
            3, 3, 48, 73, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 15, 48, 13, 6, 3, 85,
            4, 10, 12, 6, 65, 109, 97, 122, 111, 110, 49, 12, 48, 10, 6, 3, 85, 4, 11, 12, 3, 65,
            87, 83, 49, 27, 48, 25, 6, 3, 85, 4, 3, 12, 18, 97, 119, 115, 46, 110, 105, 116, 114,
            111, 45, 101, 110, 99, 108, 97, 118, 101, 115, 48, 30, 23, 13, 49, 57, 49, 48, 50, 56,
            49, 51, 50, 56, 48, 53, 90, 23, 13, 52, 57, 49, 48, 50, 56, 49, 52, 50, 56, 48, 53, 90,
            48, 73, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83, 49, 15, 48, 13, 6, 3, 85, 4, 10,
            12, 6, 65, 109, 97, 122, 111, 110, 49, 12, 48, 10, 6, 3, 85, 4, 11, 12, 3, 65, 87, 83,
            49, 27, 48, 25, 6, 3, 85, 4, 3, 12, 18, 97, 119, 115, 46, 110, 105, 116, 114, 111, 45,
            101, 110, 99, 108, 97, 118, 101, 115, 48, 118, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2,
            1, 6, 5, 43, 129, 4, 0, 34, 3, 98, 0, 4, 252, 2, 84, 235, 166, 8, 193, 243, 104, 112,
            226, 154, 218, 144, 190, 70, 56, 50, 146, 115, 110, 137, 75, 255, 246, 114, 217, 137,
            68, 75, 80, 81, 229, 52, 164, 177, 246, 219, 227, 192, 188, 88, 26, 50, 183, 177, 118,
            7, 14, 222, 18, 214, 154, 63, 234, 33, 27, 102, 231, 82, 207, 125, 209, 221, 9, 95,
            111, 19, 112, 244, 23, 8, 67, 217, 220, 16, 1, 33, 228, 207, 99, 1, 40, 9, 102, 68,
            135, 201, 121, 98, 132, 48, 77, 197, 63, 244, 163, 66, 48, 64, 48, 15, 6, 3, 85, 29,
            19, 1, 1, 255, 4, 5, 48, 3, 1, 1, 255, 48, 29, 6, 3, 85, 29, 14, 4, 22, 4, 20, 144, 37,
            181, 13, 217, 5, 71, 231, 150, 195, 150, 250, 114, 157, 207, 153, 169, 223, 75, 150,
            48, 14, 6, 3, 85, 29, 15, 1, 1, 255, 4, 4, 3, 2, 1, 134, 48, 10, 6, 8, 42, 134, 72,
            206, 61, 4, 3, 3, 3, 105, 0, 48, 102, 2, 49, 0, 163, 127, 47, 145, 161, 201, 189, 94,
            231, 184, 98, 124, 22, 152, 210, 85, 3, 142, 31, 3, 67, 249, 91, 99, 169, 98, 140, 61,
            57, 128, 149, 69, 161, 30, 188, 191, 46, 59, 85, 216, 174, 238, 113, 180, 195, 214,
            173, 243, 2, 49, 0, 162, 243, 155, 22, 5, 178, 112, 40, 165, 221, 75, 160, 105, 181, 1,
            110, 101, 180, 251, 222, 143, 224, 6, 29, 106, 83, 25, 127, 156, 218, 245, 217, 67,
            188, 97, 252, 43, 235, 3, 203, 111, 238, 141, 35, 2, 243, 223, 246,
        ];

        let serialized_timestamp = client
            .files_read(&("/input/timestamps/".to_string() + &file.name))
            .map_ok(|chunk| chunk.to_vec())
            .try_concat()
            .await
            .unwrap();

        let mut timestamp_result: [u8; 8] = [0; 8];
        timestamp_result.copy_from_slice(&serialized_timestamp[..8]);

        let timestamp = u64::from_le_bytes(timestamp_result);
        let nitro_addoc = NitroAdDoc::from_bytes(&attestation_doc, root_cert, timestamp);
        match nitro_addoc {
            Ok(nitro_addoc) => {
                let js = nitro_addoc.to_json().unwrap();
                let payload: PayloadData = serde_json::from_str(&js).unwrap();
                let mut sorted_pcrs: Vec<(&u8, &ByteBuf)> = payload.pcrs.iter().collect();
                sorted_pcrs.sort_by_key(|a| a.0);

                let pcrs_serde = serde_cbor::to_vec(&sorted_pcrs).unwrap();
                let user_data_serde = serde_cbor::to_vec(&payload.user_data).unwrap();
                let attestation_doc_serde = serde_cbor::to_vec(&attestation_doc).unwrap();
                let timestamp_serde = serde_cbor::to_vec(&timestamp).unwrap();

                let mut hash_vec = pcrs_serde;
                hash_vec.extend_from_slice(&user_data_serde);
                hash_vec.extend_from_slice(&attestation_doc_serde);
                hash_vec.extend_from_slice(&timestamp_serde);
                let result_hash = Sha256::digest(hash_vec);

                client
                    .files_write(
                        &("/state/confirmed/".to_string() + &hex::encode(result_hash)),
                        true,
                        true,
                        Cursor::new(""),
                    )
                    .await
                    .unwrap();
            }
            Err(e) => {
                eprintln!("{:?}", e);
            }
        }
    }

    let merkle_tree_leaves: Vec<[u8; 32]> = client
        .files_ls(Some("/state/confirmed"))
        .await
        .unwrap()
        .entries
        .into_iter()
        .map(|file_name| {
            let decoded = hex::decode(file_name.name).unwrap();
            let mut result: [u8; 32] = [0; 32];
            result.copy_from_slice(&decoded[..32]);
            result
        })
        .collect();
    let merkle_tree = MerkleTree::<rs_merkle::algorithms::Sha256>::from_leaves(&merkle_tree_leaves);
    let merkle_root = merkle_tree
        .root()
        .ok_or("couldn't get the merkle root")
        .unwrap();

    let data = Cursor::new(merkle_root);

    client
        .files_write("/state/output.file", true, true, data)
        .await
        .unwrap();
}
