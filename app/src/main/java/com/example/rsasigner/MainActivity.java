package com.example.rsasigner;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.text.method.ScrollingMovementMethod;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class MainActivity extends AppCompatActivity {

    private static final String PREFS_NAME = "RSASignerPrefs";
    private static final String KEY_PRIVATE_KEY = "private_key_pem";

    private EditText etPrivateKey;
    private EditText etPayload;
    private TextView tvResult;
    private Button btnSaveKey;
    private Button btnSign;
    private Button btnCopyResult;
    private Button btnClearKey;

    private SharedPreferences prefs;

    static {
        // Register Bouncy Castle provider
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);

        etPrivateKey = findViewById(R.id.etPrivateKey);
        etPayload = findViewById(R.id.etPayload);
        tvResult = findViewById(R.id.tvResult);
        btnSaveKey = findViewById(R.id.btnSaveKey);
        btnSign = findViewById(R.id.btnSign);
        btnCopyResult = findViewById(R.id.btnCopyResult);
        btnClearKey = findViewById(R.id.btnClearKey);

        tvResult.setMovementMethod(new ScrollingMovementMethod());

        // Load saved private key
        String savedKey = prefs.getString(KEY_PRIVATE_KEY, "");
        if (!savedKey.isEmpty()) {
            etPrivateKey.setText(savedKey);
        }

        btnSaveKey.setOnClickListener(v -> savePrivateKey());
        btnSign.setOnClickListener(v -> performSign());
        btnCopyResult.setOnClickListener(v -> copyResultToClipboard());
        btnClearKey.setOnClickListener(v -> confirmClearKey());
    }

    private void savePrivateKey() {
        String keyText = etPrivateKey.getText().toString().trim();
        if (keyText.isEmpty()) {
            Toast.makeText(this, "请输入私钥", Toast.LENGTH_SHORT).show();
            return;
        }

        // Basic validation
        if (!keyText.contains("-----BEGIN") || !keyText.contains("-----END")) {
            Toast.makeText(this, "私钥格式无效，请确认是否为 PEM 格式", Toast.LENGTH_LONG).show();
            return;
        }

        prefs.edit().putString(KEY_PRIVATE_KEY, keyText).apply();
        Toast.makeText(this, "✅ 私钥已保存", Toast.LENGTH_SHORT).show();
    }

    private void performSign() {
        String pemKey = etPrivateKey.getText().toString().trim();
        String payload = etPayload.getText().toString();

        if (pemKey.isEmpty()) {
            Toast.makeText(this, "请先输入或保存私钥", Toast.LENGTH_SHORT).show();
            return;
        }

        if (payload.isEmpty()) {
            Toast.makeText(this, "请输入待签名内容", Toast.LENGTH_SHORT).show();
            return;
        }

        try {
            String signature = signData(pemKey, payload);
            tvResult.setText(signature);
            btnCopyResult.setVisibility(View.VISIBLE);
        } catch (Exception e) {
            tvResult.setText("❌ 签名失败：\n" + e.getMessage());
            btnCopyResult.setVisibility(View.GONE);
        }
    }

    /**
     * RSA PKCS1v15 + SHA-256 signing, equivalent to the Python implementation.
     * Supports both PKCS#8 ("BEGIN PRIVATE KEY") and PKCS#1 ("BEGIN RSA PRIVATE KEY").
     */
    private String signData(String pemKey, String data) throws Exception {
        PrivateKey privateKey = loadPrivateKey(pemKey);

        Signature sig = Signature.getInstance("SHA256withRSA", BouncyCastleProvider.PROVIDER_NAME);
        sig.initSign(privateKey);
        sig.update(data.getBytes("UTF-8"));
        byte[] signatureBytes = sig.sign();

        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    private PrivateKey loadPrivateKey(String pem) throws Exception {
        // Strip PEM headers
        String clean = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");

        byte[] keyBytes = Base64.getDecoder().decode(clean);

        // Try PKCS#8 first
        try {
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
            return kf.generatePrivate(spec);
        } catch (Exception e) {
            // Fall back to PKCS#1 via Bouncy Castle
            org.bouncycastle.asn1.pkcs.RSAPrivateKey rsaKey =
                    org.bouncycastle.asn1.pkcs.RSAPrivateKey.getInstance(keyBytes);
            org.bouncycastle.asn1.pkcs.PrivateKeyInfo pki =
                    new org.bouncycastle.asn1.pkcs.PrivateKeyInfo(
                            new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                                    org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.rsaEncryption,
                                    org.bouncycastle.asn1.DERNull.INSTANCE),
                            rsaKey);
            PKCS8EncodedKeySpec spec2 = new PKCS8EncodedKeySpec(pki.getEncoded());
            KeyFactory kf = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
            return kf.generatePrivate(spec2);
        }
    }

    private void copyResultToClipboard() {
        String result = tvResult.getText().toString();
        if (result.isEmpty()) return;

        ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        ClipData clip = ClipData.newPlainText("signature", result);
        clipboard.setPrimaryClip(clip);
        Toast.makeText(this, "✅ 已复制到剪贴板", Toast.LENGTH_SHORT).show();
    }

    private void confirmClearKey() {
        new AlertDialog.Builder(this)
                .setTitle("清除私钥")
                .setMessage("确定要删除已保存的私钥吗？此操作不可撤销。")
                .setPositiveButton("删除", (dialog, which) -> {
                    prefs.edit().remove(KEY_PRIVATE_KEY).apply();
                    etPrivateKey.setText("");
                    Toast.makeText(this, "私钥已清除", Toast.LENGTH_SHORT).show();
                })
                .setNegativeButton("取消", null)
                .show();
    }
}
