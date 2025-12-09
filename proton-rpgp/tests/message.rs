use pgp::types::{Fingerprint, KeyId};
use proton_rpgp::EncryptedMessage;

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn message_v4_check() {
    const MESSAGE_ARMORED: &str = include_str!("../test-data/messages/encrypted_message_v4.asc");
    const SIGNATURE_ARMORED: &str = include_str!("../test-data/signatures/signature_v4.asc");
    const KEY_PACKET: &str = "c15e0327b3a9160a712c9612010740c514efd8a8e313979cb9533800343f79e895b754606bc3d7963ca8b9e6bb4c4130c61dd36450613b81c42ad53719c94906139e00d5a297ab44f76d8874afeb63a612310935a3e773884e972aec0aa3085c";
    const DATA_PACKET: &str = "d2c048018b9acd2aee630d6e4ec52b424c7374a8e67002a119f3042f8ecee39016f5f35b634845865dd44f5fa002da5b259387b8abc7d1de56e5dc862b53075c8863195997162b62aca43edbded44f66c22ab838e9599b5998a8c065814bec926d50db8255cdd716eb9db846937fb52bb47a2fc3d76511cad13f305a048294921ba7027b9566ee2d24d06fa06f59506d5d66edc11c6942357605e90126689abca10369cf631fc3eec07c69431fc931b4a9b534c4a6abe3ce4d0963051e1cb2f7582bc8bada33dbb9b1a41dbdf6407f277e42181b05e479d31b57a9d498390c2d796b95f6836136976f090f53a46894e16cb9b6bf726ee12005d1aecd967c5970d6a59e1c3efc8ff60339a7";
    let expected_key_id = KeyId::new(hex::decode("27b3a9160a712c96").unwrap().try_into().unwrap());

    let message =
        EncryptedMessage::from_armor(MESSAGE_ARMORED.as_bytes()).expect("Failed to decode");

    let message_fail = EncryptedMessage::from_armor(SIGNATURE_ARMORED.as_bytes());
    assert!(message_fail.is_err());
    assert_eq!(
        message.as_key_packets_unchecked(),
        hex::decode(KEY_PACKET).unwrap()
    );

    assert_eq!(
        message.as_data_packet_unchecked(),
        hex::decode(DATA_PACKET).unwrap()
    );

    assert_eq!(message.encryption_key_ids(), vec![expected_key_id]);
}

#[test]
#[allow(clippy::missing_panics_doc)]
pub fn message_v6_check() {
    const MESSAGE_ARMORED: &str = include_str!("../test-data/messages/encrypted_message_v6.asc");
    const SIGNATURE_ARMORED: &str = include_str!("../test-data/signatures/signature_v6.asc");
    const KEY_PACKET: &str = "c16d062106f4e92ff0c9fc045f38570178d94ade511eef700c4c8980bec87e9add0d444a48192bf8cbd3e922591b6a0c28746ae9fd4272da24715d78c77b1de1f31d3f39b27d284f0426c199401f77dbd7d502e57ee7c394f0c514180c085953141e7b4ae745d12217a32cea0fcd86";
    const DATA_PACKET: &str = "d2c09c0209020cf802f1bd52e68f9bff4a7703814b491ab30dce7dffa068f31b21b0a7b35ceb3c17089f60ac68e5c9fb4ce26cbc4f8c138dff9bbe62376e7c1bc43cf21f44bf5e6a62b4809c662231b8d74f9f84f54d97395746bfd614108170e60991b73c61c2dcb4ace0f7e62743f2cad776b4d71d42b0017e156071cfea864a1a7fd017b36598e83eeb3bfc2f4d3ca90c14efd067ef6990216ce3d181cce9ffc2c36905524ae92c6b2b98600c1224e46f9e0447bd133500fa4d353444cf618db1347058ba473fe03c8cfb220b6f2c03ef77249286dcb92600b53155a51105f4b9d16e463d6223a7c83f1a7e212d4ab81900af502f2364ec6543f4c54ce50dac12f149216f547385637f56d393c19809d3ec9019e43df9c88880b613281bac0f4b91395cb1e43db98d0d5681b40b139b3b62e5bc74dea9bd00de7cfe69379d44bf07dfc48669b3824861873da6f795235e19b48131b906cc227bab303ef4";
    let expected_fingerprint = Fingerprint::new(
        pgp::types::KeyVersion::V6,
        hex::decode("f4e92ff0c9fc045f38570178d94ade511eef700c4c8980bec87e9add0d444a48")
            .unwrap()
            .as_slice(),
    )
    .unwrap();

    let expected_key_id = KeyId::new(hex::decode("f4e92ff0c9fc045f").unwrap().try_into().unwrap());

    let message =
        EncryptedMessage::from_armor(MESSAGE_ARMORED.as_bytes()).expect("Failed to decode");

    let message_fail = EncryptedMessage::from_armor(SIGNATURE_ARMORED.as_bytes());
    assert!(message_fail.is_err());

    assert_eq!(
        message.as_key_packets_unchecked(),
        hex::decode(KEY_PACKET).unwrap()
    );

    assert_eq!(
        message.as_data_packet_unchecked(),
        hex::decode(DATA_PACKET).unwrap()
    );

    assert_eq!(
        message.encryption_fingerprints(),
        vec![expected_fingerprint]
    );

    assert_eq!(message.encryption_key_ids(), vec![expected_key_id]);
}
