(function () {
  var SALT_LEN = 16;
  var IV_LEN = 12;
  var TAG_LEN = 16;

  function b64ToBytes(b64) {
    var bin = atob(b64);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  async function decryptPayload(password, b64) {
    var data = b64ToBytes(b64);
    var salt = data.slice(0, SALT_LEN);
    var iv = data.slice(SALT_LEN, SALT_LEN + IV_LEN);
    var tag = data.slice(SALT_LEN + IV_LEN, SALT_LEN + IV_LEN + TAG_LEN);
    var ciphertext = data.slice(SALT_LEN + IV_LEN + TAG_LEN);
    var combined = new Uint8Array(ciphertext.length + tag.length);
    combined.set(ciphertext);
    combined.set(tag, ciphertext.length);

    var keyMaterial = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveKey"]
    );

    var key = await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: 100000,
        hash: "SHA-256",
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );

    var plainBuffer = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      key,
      combined
    );

    return new TextDecoder().decode(plainBuffer);
  }

  var form = document.getElementById("login-form");
  var codeInput = document.getElementById("code");
  var errorMsg = document.getElementById("error-msg");
  var loginBox = document.getElementById("login-box");
  var viewer = document.getElementById("viewer");
  var payloadCache = null;

  async function loadPayload() {
    if (payloadCache) return payloadCache;
    var res = await fetch("content.enc", { cache: "no-store" });
    if (!res.ok) throw new Error("payload");
    payloadCache = await res.text();
    return payloadCache;
  }

  form.addEventListener("submit", async function (e) {
    e.preventDefault();
    errorMsg.style.display = "none";

    try {
      var payload = await loadPayload();
      var html = await decryptPayload(codeInput.value, payload.trim());
      loginBox.style.display = "none";
      viewer.style.display = "block";
      viewer.srcdoc = html;
      codeInput.value = "";
    } catch (err) {
      errorMsg.style.display = "block";
    }
  });
})();
