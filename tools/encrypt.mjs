/**
 * 資料HTMLを暗号化して content.enc を生成する（配布しない・ローカル実行のみ）
 * 使い方: node tools/encrypt.mjs [パスワード]
 */
import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(__dirname, "..");
const sourcePath = path.join(root, "SmartKuji_プロジェクト総合資料_v1.html");
const outputPath = path.join(root, "content.enc");
const password = process.argv[2] || "kuji2026";

const html = fs.readFileSync(sourcePath, "utf8");
const styleMatch = html.match(/<style>[\s\S]*?<\/style>/);
const templateMatch = html.match(/<template id="page-content">([\s\S]*?)<\/template>/);

let plaintext;
if (templateMatch) {
  plaintext = `<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SmartKuji PHP版バージョンアップ プロジェクト総合資料 v1.0</title>
${styleMatch[0]}
</head>
<body>
${templateMatch[1].trim()}
</body>
</html>`;
} else {
  plaintext = html;
}

const salt = crypto.randomBytes(16);
const iv = crypto.randomBytes(12);
const key = crypto.pbkdf2Sync(password, salt, 100000, 32, "sha256");
const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
const encrypted = Buffer.concat([
  cipher.update(plaintext, "utf8"),
  cipher.final(),
]);
const tag = cipher.getAuthTag();
const payload = Buffer.concat([salt, iv, tag, encrypted]);

fs.writeFileSync(outputPath, payload.toString("base64"));
console.log("Generated:", outputPath);
console.log("Password:", password);
