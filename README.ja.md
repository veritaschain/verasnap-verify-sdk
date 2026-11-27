# VeraSnap Verify SDK

VeraSnap / CPP の撮影証明をサーバー側で検証し、端末の署名鍵を登録するためのSDKです。写真を証拠として受け取る損害保険会社などを想定しています。

[English README](README.md) · [導入ガイド](docs/ja/INTEGRATION.md) · [限界と未対応事項](docs/ja/LIMITATIONS.md) · [端末鍵の登録（英語）](docs/ENROLLMENT.md) · [結果コード（英語）](docs/RESULTS.md) · [撮影SDK（設計段階・英語）](docs/CAPTURE_SDK.md)

> **アルファ版**　[v0.1.0 のリリース時](https://github.com/veritaschain/verasnap-verify-sdk/releases/tag/v0.1.0)には125件のテストが通りました。以下で指定する開発版では、[自社CI](https://github.com/veritaschain/verasnap-verify-sdk/actions/runs/46006502792)で196件のテストが通っています。鍵の再登録、Android 鍵証明の発行者と経路制約の検査、実際の RFC 3161 タイムスタンプを使った不正請求シナリオ31件、実機の Android 鍵証明チェーンを検証するテストを含みます。自社による試験であり、第三者による検証ではありません。保険会社のアプリに組み込む撮影SDKは設計段階です。1.0までにAPIが変わる可能性があります。

## できること

保険金請求の写真と、その VeraSnap 証明を受け取ったときに、次の点を監査可能な形で確認します。

- このファイルは撮影時に封印されたものか。封印後に変わっていないか（SHA-256、ES256署名）
- 独立した時刻認証局のタイムスタンプがあるか。それはいつか（RFC 3161。CMS署名と証明書チェーンまで検証）
- **保険会社自身が**ハードウェア証明を通して登録した端末鍵で署名されているか（Android Key Attestation、Apple App Attest）
- 記録された撮影時刻とタイムスタンプの時刻が整合しているか（アプリと同じ60分ルール）
- 提示されたイベントのMerkle包含証明が、そのバッチのルートと一致するか。撮影履歴の削除件数は署名されていない参考値です。履歴にすべての写真が揃っているかは、この包含証明からは判断できません。

写真に写っている内容が本当かどうかは判定しません。本物のカメラで、作り込んだ損傷を撮ることはできます。**Provenance ≠ Truth（来歴は真実ではない）**。

## インストール

Python 3.10以上を使用してください。このガイドのCLIと保険審査の実装例を使う場合は、以下の開発版コミットを指定してください。この版には v0.1.0 公開後の端末鍵登録の修正も含まれます。[鍵の再登録に関する修正](https://github.com/veritaschain/verasnap-verify-sdk/pull/1)：登録処理と手動の `keys add` は、登録済みのフィンガープリントを拒否し、失効情報を含む既存の記録を保持します。[Android 鍵証明の経路に関する修正](https://github.com/veritaschain/verasnap-verify-sdk/pull/3)：Android の鍵登録で、発行者のCA権限、鍵用途、経路長を検査し、形式が不正なチェーンと未対応の制約を拒否します。Apple とタイムスタンプ用の処理は変わっていません。汎用のPKIX検証器になったわけではありません。

```bash
python -m pip install "verasnap-verify @ git+https://github.com/veritaschain/verasnap-verify-sdk.git@1f1289ef21fea84393d42a36ee10152c25cae70e"
```

v0.1.0 と依存ライブラリを導入済みの場合は、どちらの版もバージョン表示が `0.1.0` のため、次のコマンドでSDKを再インストールしてください。

```bash
python -m pip install --force-reinstall --no-deps "verasnap-verify @ git+https://github.com/veritaschain/verasnap-verify-sdk.git@1f1289ef21fea84393d42a36ee10152c25cae70e"
```

独自の鍵登録ストアを利用している場合は、[`insert_if_absent`](docs/ENROLLMENT.md) によるアトミックな挿入を実装してください。過去の失効記録が上書きされた可能性がある場合、更新だけでは履歴を復元できないため、鍵レジストリを独立した監査記録またはバックアップと照合してください。

依存ライブラリは `cryptography`、`asn1crypto`、`cbor2` です。検証時にネットワーク通信は行いません。

## 使い方

```python
from verasnap_verify import Verifier, SqliteKeyRegistry

verifier = Verifier(registry=SqliteKeyRegistry("keys.sqlite"))
result = verifier.verify(open("proof.json", "rb").read(), media=open("photo.jpg", "rb").read())

result.level           # "green" | "yellow" | "red"
result.status          # ANCHOR_VERIFIED など
result.checks          # 各チェックの id と code（安定した識別子）
result.timestamp_time  # 完全に検証できたタイムスタンプの時刻だけ
result.signer.account_ref  # 登録済みの鍵なら、その契約者の参照ID
```

受け付ける形式は、共有用の証明JSON（`proof_version` 1.2）、内部用の `proof.json`、Evidence Pack ZIP（`media.*` と `proof.json`）です。

コマンドライン：

```bash
verasnap-verify verify proof.json --media photo.jpg --registry keys.sqlite
verasnap-verify verify evidence_pack.zip --json
```

終了コードは、緑0、黄1、赤2、入力エラー3です。

## 判定

| 色 | ステータス | 意味 |
|---|---|---|
| 緑 | `ANCHOR_VERIFIED` | タイムスタンプを完全に検証でき、不合格・警告のチェックがない。写真が未提出なら写真照合はスキップされ、手動登録鍵でも署名鍵のチェックは合格し得る |
| 黄 | `PARTIALLY_VERIFIED` | 不合格はないが、確認できなかった点がある（未登録の鍵、タイムスタンプの遅れ、信頼できないTSA、Merkle証明の省略など） |
| 黄 | `ANCHOR_PENDING` | 署名は有効だが、完全に検証できたタイムスタンプがない |
| 赤 | `SIGNATURE_INVALID` / `HASH_MISMATCH` / `ERROR` | 写真と証明が一致しない、または証明が改変されている |

緑は「VeraSnapの検証基準を満たした」という意味に限ります。撮影時刻は端末の時計の値です。

## なぜ鍵の登録が必要か

誰でもP-256の鍵を作り、AIで加工した画像に署名し、本物のRFC 3161タイムスタンプを取得できます。その証明は、署名もタイムスタンプも有効です。持てないのは、「本物の端末の中で、保険会社のアプリのために作られ、ハードウェア証明を通して契約者に登録された鍵」だけです。そのため、

- 有効な鍵では、ハードウェア証明を経た登録は `known`、手動登録は `known_unattested` になります。どちらも**緑**になり得るので、端末由来であることを要件にするときはこのコードを確認します。
- 既定の検証設定では、未登録の鍵（無料アプリの未登録鍵を含む）による証明は最高でも**黄**です。

## 推奨する運用

1. ファストトラックの候補にするには、総合判定が緑で、`media_verified` が真、`signer_key` が `known` で合格し、`signer.account_ref` が請求システムで確認した対象契約者の参照IDと一致することを確認します。緑でも他の条件が揃わない案件は通常審査に回します。
2. 証明のない写真（カメラロール、LINE、Webでの提出）：既存の事後検知AI
3. 疑義のある請求・高額案件：保険会社アプリの撮影SDKで撮り直しを依頼

事後検知を置き換えるものではなく、補完するものです。詳しくは[導入ガイド](docs/ja/INTEGRATION.md)を参照してください。

## 開示事項

本SDKは VeritasChain株式会社による自社実装です。CPP を公開する VeritasChain Standards Organization（VSO）は、同社が運営する仕様開発の取り組みです。第三者によるセキュリティ監査は受けていません。C2PA の認証も受けていません。証明が裁判所・規制当局・保険会社に採用されるかどうかを判断するものではありません。

## ライセンス

Apache License 2.0。[LICENSE](LICENSE)、[NOTICE](NOTICE) を参照してください。

連絡先：developers@veritaschain.org
