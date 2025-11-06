package crypto.utils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class ProjectInitializer {

    public static void initializeProject() {
        createDirectories();
        createSampleFiles();
        System.out.println("✅ 加密系统项目初始化完成！");
    }

    private static void createDirectories() {
        String[] dirs = {
                "keys", "input", "output", "docs",
                "keys/private", "keys/public", "keys/secret",
                "output/encrypted", "output/decrypted"
        };

        for (String dir : dirs) {
            File directory = new File(dir);
            if (!directory.exists()) {
                if (directory.mkdirs()) {
                    System.out.println("📁 创建目录: " + dir);
                }
            }
        }
    }

    private static void createSampleFiles() {
        // 创建示例输入文件
        String sampleText = "这是一个用于加密测试的示例文件。\n" +
                "This is a sample file for encryption testing.\n" +
                "Hello Crypto World!";

        try {
            Files.write(Paths.get("input/sample.txt"), sampleText.getBytes());
            System.out.println("📄 创建示例文件: input/sample.txt");

            // 创建README文件
            String readme = "# 加密系统项目\n\n" +
                    "## 功能特性\n" +
                    "- 对称加密 (AES, DES, 3DES)\n" +
                    "- 消息摘要和完整性验证\n" +
                    "- 数字签名\n" +
                    "- 密钥交换\n\n" +
                    "## 使用说明\n" +
                    "运行 Main.java 启动程序";

            Files.write(Paths.get("README.md"), readme.getBytes());
            System.out.println("📖 创建文档: README.md");

        } catch (IOException e) {
            System.out.println("⚠️ 创建示例文件时出错: " + e.getMessage());
        }
    }
}