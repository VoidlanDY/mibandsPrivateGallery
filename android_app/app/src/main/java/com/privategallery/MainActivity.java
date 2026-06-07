/**
 * PrivateGalleryCompanion - Android companion app for Xiaomi Mi Band 9 Pro
 *
 * This app allows you to:
 * 1. Import photos to the normal gallery on the watch
 * 2. Import photos to the private gallery on the watch
 * 3. Set/change the normal password
 * 4. Set/change the private password
 *
 * Communication with the watch is done via ADB (Android Debug Bridge).
 * The watch must be connected via USB/WiFi ADB.
 *
 * IMPORTANT: This app is the ONLY place where the existence of two modes
 * is visible. The watch itself never reveals this information.
 */

package com.privategallery;

import android.Manifest;
import android.content.ClipData;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.OpenableColumns;
import android.text.InputType;
import android.text.method.PasswordTransformationMethod;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "PrivateGallery";
    private static final String WATCH_NORMAL_DIR = "/data/gallery/normal/";
    private static final String WATCH_PRIVATE_DIR = "/data/gallery/private/";
    private static final String WATCH_PW_FILE = "/data/gallery/.pw";
    private static final int PIN_LENGTH = 6;
    private static final int PERMISSION_REQUEST_CODE = 100;

    private TextView statusText;
    private ProgressBar progressBar;
    private TextView normalCountText;
    private TextView privateCountText;
    private Button btnImportNormal;
    private Button btnImportPrivate;
    private Button btnSetNormalPw;
    private Button btnSetPrivatePw;

    private boolean adbAvailable = false;

    /* Activity result launcher for selecting multiple images */
    private ActivityResultLauncher<Intent> imagePickerNormalLauncher;
    private ActivityResultLauncher<Intent> imagePickerPrivateLauncher;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        initViews();
        initImagePickers();
        checkPermissions();
    }

    private void initViews() {
        statusText = findViewById(R.id.status_text);
        progressBar = findViewById(R.id.progress_bar);
        normalCountText = findViewById(R.id.normal_count_text);
        privateCountText = findViewById(R.id.private_count_text);
        btnImportNormal = findViewById(R.id.btn_import_normal);
        btnImportPrivate = findViewById(R.id.btn_import_private);
        btnSetNormalPw = findViewById(R.id.btn_set_normal_pw);
        btnSetPrivatePw = findViewById(R.id.btn_set_private_pw);

        /* Set click listeners */
        btnImportNormal.setOnClickListener(v -> pickImages(true));
        btnImportPrivate.setOnClickListener(v -> pickImages(false));
        btnSetNormalPw.setOnClickListener(v -> showSetPasswordDialog(true));
        btnSetPrivatePw.setOnClickListener(v -> showSetPasswordDialog(false));

        /* Verify button - opens dialog to show password verification UI */
        Button btnVerify = findViewById(R.id.btn_verify);
        btnVerify.setOnClickListener(v -> showVerifyPasswordDialog());
    }

    private void initImagePickers() {
        imagePickerNormalLauncher = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            result -> {
                if (result.getResultCode() == RESULT_OK && result.getData() != null) {
                    handleSelectedImages(result.getData(), true);
                }
            }
        );

        imagePickerPrivateLauncher = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            result -> {
                if (result.getResultCode() == RESULT_OK && result.getData() != null) {
                    handleSelectedImages(result.getData(), false);
                }
            }
        );
    }

    private void checkPermissions() {
        String[] permissions;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            permissions = new String[]{
                Manifest.permission.READ_MEDIA_IMAGES
            };
        } else {
            permissions = new String[]{
                Manifest.permission.READ_EXTERNAL_STORAGE,
                Manifest.permission.WRITE_EXTERNAL_STORAGE
            };
        }

        boolean allGranted = true;
        for (String perm : permissions) {
            if (ContextCompat.checkSelfPermission(this, perm)
                    != PackageManager.PERMISSION_GRANTED) {
                allGranted = false;
                break;
            }
        }

        if (!allGranted) {
            ActivityCompat.requestPermissions(this, permissions,
                    PERMISSION_REQUEST_CODE);
        } else {
            checkAdbConnection();
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions,
                                           @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == PERMISSION_REQUEST_CODE) {
            boolean allGranted = true;
            for (int result : grantResults) {
                if (result != PackageManager.PERMISSION_GRANTED) {
                    allGranted = false;
                    break;
                }
            }
            if (allGranted) {
                checkAdbConnection();
            } else {
                statusText.setText("需要存储权限才能导入图片");
                Toast.makeText(this,
                    "请授予存储权限以使用完整功能",
                    Toast.LENGTH_LONG).show();
            }
        }
    }

    /**
     * Check if ADB is available and the watch is connected.
     */
    private void checkAdbConnection() {
        statusText.setText("正在检查手表连接...");
        progressBar.setVisibility(View.VISIBLE);

        new AsyncTask<Void, Void, Boolean>() {
            @Override
            protected Boolean doInBackground(Void... voids) {
                try {
                    Process p = new ProcessBuilder("adb", "devices")
                        .redirectErrorStream(true)
                        .start();
                    BufferedReader reader = new BufferedReader(
                        new InputStreamReader(p.getInputStream()));
                    String line;
                    int deviceCount = 0;
                    while ((line = reader.readLine()) != null) {
                        if (line.endsWith("\tdevice")) {
                            deviceCount++;
                        }
                    }
                    p.waitFor();
                    return deviceCount > 0;
                } catch (Exception e) {
                    Log.e(TAG, "ADB check failed", e);
                    return false;
                }
            }

            @Override
            protected void onPostExecute(Boolean result) {
                progressBar.setVisibility(View.GONE);
                adbAvailable = result;
                if (result) {
                    statusText.setText("✓ 手表已连接");
                    refreshFileCounts();
                } else {
                    statusText.setText("✗ 未检测到手表的ADB连接\n请确保手表已通过USB/WiFi连接");
                }
            }
        }.execute();
    }

    /**
     * Refresh the file counts for normal and private galleries.
     */
    private void refreshFileCounts() {
        if (!adbAvailable) return;

        new AsyncTask<Void, Void, int[]>() {
            @Override
            protected int[] doInBackground(Void... voids) {
                int normalCount = countFilesInDir(WATCH_NORMAL_DIR);
                int privateCount = countFilesInDir(WATCH_PRIVATE_DIR);
                return new int[]{normalCount, privateCount};
            }

            @Override
            protected void onPostExecute(int[] counts) {
                normalCountText.setText("普通图库: " + counts[0] + " 张图片");
                privateCountText.setText("私密图库: " + counts[1] + " 张图片");
            }
        }.execute();
    }

    /**
     * Count files in a directory on the watch via ADB.
     */
    private int countFilesInDir(String dirPath) {
        try {
            Process p = new ProcessBuilder(
                "adb", "shell", "ls", dirPath)
                .redirectErrorStream(true)
                .start();
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(p.getInputStream()));
            int count = 0;
            while (reader.readLine() != null) count++;
            p.waitFor();
            return (count >= 0) ? count : 0;
        } catch (Exception e) {
            return 0;
        }
    }

    /**
     * Open image picker for selecting photos.
     * @param isNormal true = normal gallery, false = private gallery
     */
    private void pickImages(boolean isNormal) {
        if (!adbAvailable) {
            Toast.makeText(this, "请先确保手表已连接", Toast.LENGTH_SHORT).show();
            return;
        }

        Intent intent = new Intent(Intent.ACTION_GET_CONTENT);
        intent.setType("image/*");
        intent.putExtra(Intent.EXTRA_ALLOW_MULTIPLE, true);
        intent.addCategory(Intent.CATEGORY_OPENABLE);

        if (isNormal) {
            imagePickerNormalLauncher.launch(intent);
        } else {
            imagePickerPrivateLauncher.launch(intent);
        }
    }

    /**
     * Handle selected images from picker.
     */
    private void handleSelectedImages(Intent data, boolean isNormal) {
        List<Uri> uris = new ArrayList<>();
        ClipData clipData = data.getClipData();

        if (clipData != null) {
            for (int i = 0; i < clipData.getItemCount(); i++) {
                uris.add(clipData.getItemAt(i).getUri());
            }
        } else if (data.getData() != null) {
            uris.add(data.getData());
        }

        if (!uris.isEmpty()) {
            String targetDir = isNormal ? WATCH_NORMAL_DIR : WATCH_PRIVATE_DIR;
            String label = isNormal ? "普通" : "私密";
            statusText.setText("正在导入" + uris.size() + "张图片到" + label + "图库...");
            new ImportImagesTask(targetDir, isNormal).execute(
                uris.toArray(new Uri[0]));
        }
    }

    /**
     * AsyncTask to import images to the watch via ADB.
     */
    private class ImportImagesTask extends AsyncTask<Uri, Integer, Integer> {
        private final String targetDir;
        private final boolean isNormal;

        ImportImagesTask(String targetDir, boolean isNormal) {
            this.targetDir = targetDir;
            this.isNormal = isNormal;
        }

        @Override
        protected void onPreExecute() {
            progressBar.setVisibility(View.VISIBLE);
            progressBar.setMax(100);
            btnImportNormal.setEnabled(false);
            btnImportPrivate.setEnabled(false);
        }

        @Override
        protected Integer doInBackground(Uri... uris) {
            int successCount = 0;

            /* Ensure target directory exists */
            runAdbShell("mkdir -p " + targetDir);

            for (int i = 0; i < uris.length; i++) {
                Uri uri = uris[i];

                /* Get file name from URI */
                String fileName = getFileName(uri);
                if (fileName == null) {
                    fileName = "image_" + System.currentTimeMillis() + ".png";
                }

                /* Copy file to local temp */
                File tempFile = new File(getCacheDir(), fileName);
                if (copyUriToFile(uri, tempFile)) {
                    /* Push to watch */
                    String watchPath = targetDir + fileName;
                    if (adbPush(tempFile.getAbsolutePath(), watchPath)) {
                        successCount++;
                    }
                    /* Clean up temp file */
                    tempFile.delete();
                }

                publishProgress((i + 1) * 100 / uris.length);
            }

            return successCount;
        }

        @Override
        protected void onProgressUpdate(Integer... values) {
            progressBar.setProgress(values[0]);
        }

        @Override
        protected void onPostExecute(Integer successCount) {
            progressBar.setVisibility(View.GONE);
            btnImportNormal.setEnabled(true);
            btnImportPrivate.setEnabled(true);

            String label = isNormal ? "普通" : "私密";
            statusText.setText("✓ 已导入 " + successCount + " 张图片到" + label + "图库");
            refreshFileCounts();

            /* Restart the gallery app on watch to refresh */
            runAdbShell("killall pgallery 2>/dev/null; pgallery &");
        }
    }

    /**
     * Run an ADB shell command.
     */
    private void runAdbShell(String command) {
        try {
            Process p = new ProcessBuilder("adb", "shell", command)
                .redirectErrorStream(true)
                .start();
            p.waitFor();
        } catch (Exception e) {
            Log.e(TAG, "ADB shell command failed: " + command, e);
        }
    }

    /**
     * Push a local file to the watch via ADB.
     */
    private boolean adbPush(String localPath, String remotePath) {
        try {
            Process p = new ProcessBuilder(
                "adb", "push", localPath, remotePath)
                .redirectErrorStream(true)
                .start();
            int exitCode = p.waitFor();
            return exitCode == 0;
        } catch (Exception e) {
            Log.e(TAG, "ADB push failed", e);
            return false;
        }
    }

    /**
     * Get the display name from a content URI.
     */
    private String getFileName(Uri uri) {
        String fileName = null;
        if (uri.getScheme() != null && uri.getScheme().equals("content")) {
            try (Cursor cursor = getContentResolver().query(uri, null,
                    null, null, null)) {
                if (cursor != null && cursor.moveToFirst()) {
                    int nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                    if (nameIndex >= 0) {
                        fileName = cursor.getString(nameIndex);
                    }
                }
            } catch (Exception e) {
                Log.e(TAG, "Failed to get file name", e);
            }
        }
        if (fileName == null) {
            fileName = "image_" + System.currentTimeMillis() + ".png";
        }
        return fileName;
    }

    /**
     * Copy a content URI to a local temp file.
     */
    private boolean copyUriToFile(Uri uri, File destFile) {
        try (InputStream in = getContentResolver().openInputStream(uri);
             OutputStream out = new FileOutputStream(destFile)) {
            if (in == null) return false;
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
            return true;
        } catch (IOException e) {
            Log.e(TAG, "Failed to copy URI to file", e);
            return false;
        }
    }

    /**
     * Show dialog to set/change a password.
     * @param isNormal true = set normal password, false = set private password
     */
    private void showSetPasswordDialog(boolean isNormal) {
        if (!adbAvailable) {
            Toast.makeText(this, "请先确保手表已连接", Toast.LENGTH_SHORT).show();
            return;
        }

        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        String title = isNormal ? "设置普通密码" : "设置私密密码";
        builder.setTitle(title);

        /* Create dialog layout */
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(50, 20, 50, 10);

        final EditText pwInput = new EditText(this);
        pwInput.setHint("请输入" + PIN_LENGTH + "位数字密码");
        pwInput.setInputType(InputType.TYPE_CLASS_NUMBER |
                             InputType.TYPE_NUMBER_VARIATION_PASSWORD);
        pwInput.setTransformationMethod(PasswordTransformationMethod.getInstance());
        layout.addView(pwInput);

        final EditText pwConfirm = new EditText(this);
        pwConfirm.setHint("请再次输入密码确认");
        pwConfirm.setInputType(InputType.TYPE_CLASS_NUMBER |
                               InputType.TYPE_NUMBER_VARIATION_PASSWORD);
        pwConfirm.setTransformationMethod(PasswordTransformationMethod.getInstance());
        layout.addView(pwConfirm);

        builder.setView(layout);

        builder.setPositiveButton("确定", (dialog, which) -> {
            String pw1 = pwInput.getText().toString();
            String pw2 = pwConfirm.getText().toString();

            if (pw1.length() != PIN_LENGTH) {
                Toast.makeText(this,
                    "密码必须是" + PIN_LENGTH + "位数字",
                    Toast.LENGTH_SHORT).show();
                return;
            }
            if (!pw1.equals(pw2)) {
                Toast.makeText(this, "两次输入的密码不一致", Toast.LENGTH_SHORT).show();
                return;
            }
            if (!pw1.matches("\\d+")) {
                Toast.makeText(this, "密码只能包含数字", Toast.LENGTH_SHORT).show();
                return;
            }

            updateWatchPassword(isNormal, pw1);
        });

        builder.setNegativeButton("取消", null);
        builder.show();
    }

    /**
     * Update the password on the watch.
     *
     * Writes the password hash directly to the watch's password file.
     * Format: first 32 bytes = SHA-256(normal_password)
     *         next 32 bytes  = SHA-256(private_password)
     */
    private void updateWatchPassword(boolean isNormal, String newPin) {
        new AsyncTask<Void, Void, Boolean>() {
            @Override
            protected void onPreExecute() {
                progressBar.setVisibility(View.VISIBLE);
                statusText.setText("正在更新密码...");
            }

            @Override
            protected Boolean doInBackground(Void... voids) {
                try {
                    /* Compute SHA-256 hash */
                    MessageDigest md = MessageDigest.getInstance("SHA-256");
                    byte[] newHash = md.digest(
                        newPin.getBytes(StandardCharsets.UTF_8));

                    /* Download existing password file */
                    File localPwFile = new File(getCacheDir(), "gallery_pw.bin");
                    boolean hasExisting = adbPull(WATCH_PW_FILE,
                        localPwFile.getAbsolutePath());

                    byte[] normalHash;
                    byte[] privateHash;

                    if (hasExisting && localPwFile.length() >= 64) {
                        /* Read existing hashes */
                        try (FileInputStream fis =
                                new FileInputStream(localPwFile)) {
                            normalHash = new byte[32];
                            privateHash = new byte[32];
                            fis.read(normalHash);
                            fis.read(privateHash);
                        }
                    } else {
                        /* Initialize with defaults */
                        normalHash = new byte[32];
                        privateHash = new byte[32];
                        for (int i = 0; i < 32; i++) {
                            privateHash[i] = (byte) 0xFF;
                        }
                    }

                    /* Update the appropriate hash */
                    if (isNormal) {
                        normalHash = newHash;
                    } else {
                        privateHash = newHash;
                    }

                    /* Write new password file locally */
                    try (FileOutputStream fos =
                            new FileOutputStream(localPwFile)) {
                        fos.write(normalHash);
                        fos.write(privateHash);
                    }

                    /* Push back to watch */
                    return adbPush(localPwFile.getAbsolutePath(),
                                   WATCH_PW_FILE);
                } catch (NoSuchAlgorithmException | IOException e) {
                    Log.e(TAG, "Failed to update password", e);
                    return false;
                }
            }

            @Override
            protected void onPostExecute(Boolean success) {
                progressBar.setVisibility(View.GONE);
                String label = isNormal ? "普通" : "私密";
                if (success) {
                    statusText.setText("✓ " + label + "密码已更新");
                    Toast.makeText(MainActivity.this,
                        label + "密码设置成功", Toast.LENGTH_SHORT).show();
                } else {
                    statusText.setText("✗ " + label + "密码更新失败");
                    Toast.makeText(MainActivity.this,
                        "密码更新失败，请检查连接", Toast.LENGTH_SHORT).show();
                }
            }
        }.execute();
    }

    /**
     * Pull a file from the watch via ADB.
     */
    private boolean adbPull(String remotePath, String localPath) {
        try {
            Process p = new ProcessBuilder(
                "adb", "pull", remotePath, localPath)
                .redirectErrorStream(true)
                .start();
            int exitCode = p.waitFor();
            return exitCode == 0;
        } catch (Exception e) {
            Log.e(TAG, "ADB pull failed", e);
            return false;
        }
    }

    /**
     * Show a dialog to verify a password.
     * This allows user to test which mode a password triggers
     * (useful for verifying dual-password setup).
     */
    private void showVerifyPasswordDialog() {
        if (!adbAvailable) {
            Toast.makeText(this, "请先确保手表已连接", Toast.LENGTH_SHORT).show();
            return;
        }

        AlertDialog.Builder builder = new AlertDialog.Builder(this);
        builder.setTitle("验证密码");

        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(50, 20, 50, 10);

        final EditText pwInput = new EditText(this);
        pwInput.setHint("输入密码验证对应模式");
        pwInput.setInputType(InputType.TYPE_CLASS_NUMBER |
                             InputType.TYPE_NUMBER_VARIATION_PASSWORD);
        pwInput.setTransformationMethod(PasswordTransformationMethod.getInstance());
        layout.addView(pwInput);

        final TextView resultText = new TextView(this);
        resultText.setPadding(0, 20, 0, 0);
        resultText.setTextColor(0xFFCCCCCC);
        resultText.setText("输入密码后可验证该密码对应查看哪种图库");
        layout.addView(resultText);

        builder.setView(layout);

        builder.setPositiveButton("验证", (dialog, which) -> {
            String pin = pwInput.getText().toString();
            if (pin.length() != PIN_LENGTH || !pin.matches("\\d+")) {
                Toast.makeText(this,
                    "请输入" + PIN_LENGTH + "位数字密码",
                    Toast.LENGTH_SHORT).show();
                return;
            }
            verifyPassword(pin, resultText);
        });

        builder.setNegativeButton("取消", null);
        builder.show();
    }

    /**
     * Verify which mode a given password maps to.
     */
    private void verifyPassword(String pin, TextView resultText) {
        new AsyncTask<Void, Void, String>() {
            @Override
            protected String doInBackground(Void... voids) {
                try {
                    /* Compute hash */
                    MessageDigest md = MessageDigest.getInstance("SHA-256");
                    byte[] inputHash = md.digest(
                        pin.getBytes(StandardCharsets.UTF_8));

                    /* Download password file */
                    File localPwFile = new File(getCacheDir(),
                        "gallery_pw_verify.bin");
                    if (!adbPull(WATCH_PW_FILE,
                            localPwFile.getAbsolutePath())) {
                        return "无法读取手表的密码文件";
                    }

                    if (localPwFile.length() < 64) {
                        return "密码文件格式不正确";
                    }

                    byte[] normalHash = new byte[32];
                    byte[] privateHash = new byte[32];

                    try (FileInputStream fis =
                            new FileInputStream(localPwFile)) {
                        fis.read(normalHash);
                        fis.read(privateHash);
                    }

                    /* Compare in constant-time manner */
                    boolean isNormal = constantTimeEquals(inputHash, normalHash);
                    boolean isPrivate = constantTimeEquals(inputHash, privateHash);

                    if (isPrivate && isNormal) {
                        return "匹配: 普通图库 和 私密图库（两个密码相同）\n⚠ 建议设置不同的密码以确保隐私";
                    } else if (isPrivate) {
                        return "匹配: ★ 私密图库 ★";
                    } else if (isNormal) {
                        return "匹配: 普通图库";
                    } else {
                        return "不匹配: 既不是普通密码也不是私密密码";
                    }
                } catch (Exception e) {
                    Log.e(TAG, "Verify failed", e);
                    return "验证过程出错: " + e.getMessage();
                }
            }

            @Override
            protected void onPostExecute(String result) {
                resultText.setText(result);
                if (result.contains("私密")) {
                    resultText.setTextColor(0xFFFF6666);
                } else if (result.contains("普通")) {
                    resultText.setTextColor(0xFF66AAFF);
                } else {
                    resultText.setTextColor(0xFFFFAA00);
                }
            }
        }.execute();
    }

    /**
     * Constant-time byte array comparison.
     */
    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) {
            diff |= (a[i] ^ b[i]);
        }
        return diff == 0;
    }
}
