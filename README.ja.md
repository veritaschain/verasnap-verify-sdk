# VeraSnap Verify SDK

VeraSnap / CPP の撮影証明をサーバー側で検証し、端末の署名鍵を登録するためのSDKです。写真を証拠として受け取る損害保険会社などを想定しています。

[English README](README.md) · [導入ガイド](docs/ja/INTEGRATION.md) · [限界と未対応事項](docs/ja/LIMITATIONS.md) · [端末鍵の登録（英語）](docs/ENROLLMENT.md) · [結果コード（英語）](docs/RESULTS.md) · [撮影SDK（設計段階・英語）](docs/CAPTURE_SDK.md)

> **状態：0.1.0（アルファ版）。** 検証と鍵登録の処理は完成しており、テスト125件を通しています。そのうち31件は不正請求を想定したシナリオで、実際のRFC 3161タイムスタンプと、実機のAndroid鍵証明チェーンを使っています。保険会社のアプリに組み込む撮影SDKは設計段階で、コードはまだありません。1.0までにAPIが変わる可能性があります。

## できること

保険金請求の写真と、その VeraSnap 証明を受け取ったときに、次の点を監査可能な形で確認します。

- このファイルは撮影時に封印されたものか。封印後に変わっていないか（SHA-256、ES256署名）
- 独立した時刻認証局のタイムスタンプがあるか。それはいつか（RFC 3161。CMS署名と証明書チェーンまで検証）
- **保険会社自身が**ハードウェア証明を通して登録した端末鍵で署名されているか（Android Key Attestation、Apple App Attest）
- 記録された撮影時刻とタイムスタンプの時刻が整合しているか（アプリと同じ60分ルール）
- 撮影履歴から写真が抜かれていないか（Merkle包含証明。チェーン情報は参考値として表示）

写真に写っている内容が本当かどうかは判定しません。本物のカメラで、作り込んだ損傷を撮ることはできます。**Provenance ≠ Truth（来歴は真実ではない）**。

## インストール

Python 3.10以上。

```bash
pip install git+https://github.com/veritaschain/verasnap-verify-sdk
```

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
| 緑 | `ANCHOR_VERIFIED` | すべてのチェックに合格。署名後に変わっておらず、登録済みの鍵で署名され、タイムスタンプを完全に検証でき、それが記録上の撮影時刻から60分以内に取得されている |
| 黄 | `PARTIALLY_VERIFIED` | 不合格はないが、確認できなかった点がある（未登録の鍵、タイムスタンプの遅れ、信頼できないTSA、Merkle証明の省略など） |
| 黄 | `ANCHOR_PENDING` | 署名は有効だが、完全に検証できたタイムスタンプがない |
| 赤 | `SIGNATURE_INVALID` / `HASH_MISMATCH` / `ERROR` | 写真と証明が一致しない、または証明が改変されている |

緑は「VeraSnapの検証基準を満たした」という意味に限ります。撮影時刻は端末の時計の値です。

## なぜ鍵の登録が必要か

誰でもP-256の鍵を作り、AIで加工した画像に署名し、本物のRFC 3161タイムスタンプを取得できます。その証明は、署名もタイムスタンプも有効です。持てないのは、「本物の端末の中で、保険会社のアプリのために作られ、ハードウェア証明を通して契約者に登録された鍵」だけです。そのため、

- 登録済みの鍵で署名された証明は**緑**になり得ます。
- それ以外の鍵（無料の消費者向けアプリの鍵を含む）で署名された証明は、最高でも**黄**です。

## 推奨する運用

1. 登録済みの鍵による証明付きで、緑の写真：ファストトラック
2. 証明のない写真（カメラロール、LINE、Webでの提出）：既存の事後検知AI
3. 疑義のある請求・高額案件：保険会社アプリの撮影SDKで撮り直しを依頼

事後検知を置き換えるものではなく、補完するものです。詳しくは[導入ガイド](docs/ja/INTEGRATION.md)を参照してください。

## 開示事項

本SDKは VeritasChain株式会社による自社実装です。同社は CPP を公開する VeritasChain Standards Organization と創業者が同じです。第三者によるセキュリティ監査は受けていません。C2PA の認証も受けていません。証明が裁判所・規制当局・保険会社に採用されるかどうかを判断するものではありません。

## ライセンス

Apache License 2.0。[LICENSE](LICENSE)、[NOTICE](NOTICE) を参照してください。

連絡先：developers@veritaschain.org
