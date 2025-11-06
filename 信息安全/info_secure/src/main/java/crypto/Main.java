// src/main/java/crypto/Main.java
package crypto;

import crypto.core.CryptoManager;
import crypto.core.FileProcessor;
import crypto.utils.ProjectInitializer;

import java.util.Scanner;

public class Main {
    private static CryptoManager cryptoManager;
    private static Scanner scanner;

    public static void main(String[] args) {
        System.out.println("🔐 加密系统启动中...");

        // 初始化项目
        ProjectInitializer.initializeProject();

        // 创建加密管理器
        cryptoManager = new CryptoManager();
        scanner = new Scanner(System.in);

        System.out.println("🎉 加密系统初始化完成！");
        cryptoManager.listCapabilities();

        // 显示主菜单
        showMainMenu();
    }

    private static void showMainMenu() {
        while (true) {
            System.out.println("\n" + "=".repeat(50));
            System.out.println("            🔐 加密系统主菜单");
            System.out.println("=".repeat(50));
            System.out.println("1. 文件加密/解密");
            System.out.println("2. 密钥管理");
            System.out.println("3. 哈希计算与完整性验证");
            System.out.println("4. 数字签名");
            System.out.println("5. 密钥交换演示");
            System.out.println("6. 系统状态检查");
            System.out.println("7. 功能演示");
            System.out.println("0. 退出系统");
            System.out.println("=".repeat(50));
            System.out.print("请选择操作 (0-7): ");

            String choice = scanner.nextLine();

            switch (choice) {
                case "1":
                    fileCryptoMenu();
                    break;
                case "2":
                    keyManagementMenu();
                    break;
                case "3":
                    hashMenu();
                    break;
                case "4":
                    signatureMenu();
                    break;
                case "5":
                    keyExchangeMenu();
                    break;
                case "6":
                    cryptoManager.systemStatus();
                    break;
                case "7":
                    demonstrateAllFeatures();
                    break;
                case "0":
                    System.out.println("👋 感谢使用加密系统，再见！");
                    return;
                default:
                    System.out.println("❌ 无效选择，请重新输入！");
            }
        }
    }

    private static void fileCryptoMenu() {
        System.out.println("\n📁 文件加密/解密菜单");
        System.out.println("1. 加密文件");
        System.out.println("2. 解密文件");
        System.out.println("3. 返回主菜单");
        System.out.print("请选择: ");

        String choice = scanner.nextLine();

        try {
            switch (choice) {
                case "1":
                    System.out.print("请输入要加密的文件路径: ");
                    String inputFile = scanner.nextLine();
                    System.out.print("请输入加密后输出文件路径: ");
                    String outputFile = scanner.nextLine();
                    System.out.print("选择算法 (AES/DES/3DES): ");
                    String algorithm = scanner.nextLine();
                    System.out.print("输入密钥名称 (留空则自动生成): ");
                    String keyName = scanner.nextLine();

                    cryptoManager.encryptFile(inputFile, outputFile, algorithm,
                            keyName.isEmpty() ? null : keyName);
                    break;

                case "2":
                    System.out.print("请输入要解密的文件路径: ");
                    inputFile = scanner.nextLine();
                    System.out.print("请输入解密后输出文件路径: ");
                    outputFile = scanner.nextLine();
                    System.out.print("选择算法 (AES/DES/3DES): ");
                    algorithm = scanner.nextLine();
                    System.out.print("输入密钥名称: ");
                    keyName = scanner.nextLine();

                    cryptoManager.decryptFile(inputFile, outputFile, algorithm, keyName);
                    break;

                case "3":
                    return;

                default:
                    System.out.println("❌ 无效选择");
            }
        } catch (Exception e) {
            System.out.println("❌ 操作失败: " + e.getMessage());
        }
    }

    private static void keyManagementMenu() {
        System.out.println("\n🔑 密钥管理菜单");
        System.out.println("1. 生成新密钥");
        System.out.println("2. 列出所有密钥");
        System.out.println("3. 返回主菜单");
        System.out.print("请选择: ");

        String choice = scanner.nextLine();

        try {
            switch (choice) {
                case "1":
                    System.out.print("选择算法 (AES/DES/3DES): ");
                    String algorithm = scanner.nextLine();
                    System.out.print("输入密钥名称: ");
                    String keyName = scanner.nextLine();

                    cryptoManager.generateSymmetricKey(algorithm);
                    break;

                case "2":
                    crypto.core.KeyManager keyManager = new crypto.core.KeyManager();
                    keyManager.listKeys();
                    break;

                case "3":
                    return;

                default:
                    System.out.println("❌ 无效选择");
            }
        } catch (Exception e) {
            System.out.println("❌ 操作失败: " + e.getMessage());
        }
    }

    private static void hashMenu() {
        System.out.println("\n📊 哈希计算与完整性验证");
        System.out.println("1. 计算文件哈希");
        System.out.println("2. 验证文件完整性");
        System.out.println("3. 返回主菜单");
        System.out.print("请选择: ");

        String choice = scanner.nextLine();

        try {
            switch (choice) {
                case "1":
                    System.out.print("请输入文件路径: ");
                    String filePath = scanner.nextLine();
                    System.out.print("选择算法 (SHA-1/SHA-256): ");
                    String algorithm = scanner.nextLine();

                    String hash = cryptoManager.calculateFileHash(filePath, algorithm);
                    System.out.println("✅ 文件哈希值: " + hash);
                    break;

                case "2":
                    System.out.print("请输入文件路径: ");
                    filePath = scanner.nextLine();
                    System.out.print("输入期望的哈希值: ");
                    String expectedHash = scanner.nextLine();
                    System.out.print("选择算法 (SHA-1/SHA-256): ");
                    algorithm = scanner.nextLine();

                    cryptoManager.verifyFileIntegrity(filePath, expectedHash, algorithm);
                    break;

                case "3":
                    return;

                default:
                    System.out.println("❌ 无效选择");
            }
        } catch (Exception e) {
            System.out.println("❌ 操作失败: " + e.getMessage());
        }
    }

    private static void signatureMenu() {
        System.out.println("\n✍️  数字签名菜单");
        System.out.println("1. 创建签名身份");
        System.out.println("2. 对文件签名");
        System.out.println("3. 验证文件签名");
        System.out.println("4. 返回主菜单");
        System.out.print("请选择: ");

        String choice = scanner.nextLine();

        try {
            switch (choice) {
                case "1":
                    System.out.print("输入身份名称: ");
                    String identityName = scanner.nextLine();
                    cryptoManager.createSignatureIdentity(identityName);
                    break;

                case "2":
                    System.out.print("请输入要签名的文件路径: ");
                    String filePath = scanner.nextLine();
                    System.out.print("输入身份名称: ");
                    identityName = scanner.nextLine();
                    cryptoManager.signFile(filePath, identityName);
                    break;

                case "3":
                    System.out.print("请输入要验证的文件路径: ");
                    filePath = scanner.nextLine();
                    System.out.print("输入签名文件路径: ");
                    String signatureFile = scanner.nextLine();
                    System.out.print("输入身份名称: ");
                    identityName = scanner.nextLine();
                    cryptoManager.verifyFileSignature(filePath, signatureFile, identityName);
                    break;

                case "4":
                    return;

                default:
                    System.out.println("❌ 无效选择");
            }
        } catch (Exception e) {
            System.out.println("❌ 操作失败: " + e.getMessage());
        }
    }

    private static void keyExchangeMenu() {
        System.out.println("\n🔑 密钥交换演示");
        System.out.println("即将演示Diffie-Hellman密钥交换协议...");

        try {
            cryptoManager.demonstrateKeyExchange();
        } catch (Exception e) {
            System.out.println("❌ 密钥交换演示失败: " + e.getMessage());
        }

        System.out.print("\n按回车键继续...");
        scanner.nextLine();
    }

    private static void demonstrateAllFeatures() {
        System.out.println("\n🎯 开始完整功能演示...");

        try {
            // 1. 创建测试文件
            String testFile = "input/demo_test.txt";
            FileProcessor.writeStringToFile("这是加密系统功能演示的测试文件内容！", testFile);
            System.out.println("✅ 创建测试文件: " + testFile);

            // 2. 计算哈希
            String hash = cryptoManager.calculateFileHash(testFile, "SHA-256");
            System.out.println("✅ 计算文件哈希: " + hash);

            // 3. 加密文件
            cryptoManager.encryptFile(testFile, "output/encrypted_demo.dat", "AES", "demo_key");

            // 4. 解密文件
            cryptoManager.decryptFile("output/encrypted_demo.dat", "output/decrypted_demo.txt", "AES", "demo_key");

            // 5. 创建数字签名身份
            cryptoManager.createSignatureIdentity("demo_user");

            // 6. 对文件签名
            cryptoManager.signFile(testFile, "demo_user");

            // 7. 验证签名
            cryptoManager.verifyFileSignature(testFile, testFile + ".signature", "demo_user");

            System.out.println("🎉 所有功能演示完成！");

        } catch (Exception e) {
            System.out.println("❌ 演示过程中出错: " + e.getMessage());
            e.printStackTrace();
        }

        System.out.print("\n按回车键继续...");
        scanner.nextLine();
    }
}