package crypto.core;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class FileProcessor {

    /**
     * 读取文件内容为字节数组
     */
    public static byte[] readFileToBytes(String filePath) throws IOException {
        Path path = Paths.get(filePath);
        if (!Files.exists(path)) {
            throw new FileNotFoundException("文件不存在: " + filePath);
        }
        return Files.readAllBytes(path);
    }

    /**
     * 将字节数组写入文件
     */
    public static void writeBytesToFile(byte[] data, String filePath) throws IOException {
        Path path = Paths.get(filePath);

        // 确保目录存在
        Path parentDir = path.getParent();
        if (parentDir != null && !Files.exists(parentDir)) {
            Files.createDirectories(parentDir);
        }

        Files.write(path, data);
        System.out.println("✅ 文件已保存: " + filePath);
    }

    /**
     * 读取文本文件内容
     */
    public static String readFileToString(String filePath) throws IOException {
        byte[] bytes = readFileToBytes(filePath);
        return new String(bytes, "UTF-8");
    }

    /**
     * 将文本写入文件
     */
    public static void writeStringToFile(String content, String filePath) throws IOException {
        writeBytesToFile(content.getBytes("UTF-8"), filePath);
    }

    /**
     * 加密文件
     */
    public static void encryptFile(String inputFilePath, String outputFilePath,
                                   byte[] encryptedData) throws IOException {
        writeBytesToFile(encryptedData, outputFilePath);
        System.out.println("🔒 文件加密完成: " + inputFilePath + " → " + outputFilePath);
    }

    /**
     * 解密文件
     */
    public static void decryptFile(String inputFilePath, String outputFilePath,
                                   byte[] decryptedData) throws IOException {
        writeBytesToFile(decryptedData, outputFilePath);
        System.out.println("🔓 文件解密完成: " + inputFilePath + " → " + outputFilePath);
    }

    /**
     * 获取文件信息
     */
    public static FileInfo getFileInfo(String filePath) throws IOException {
        Path path = Paths.get(filePath);
        if (!Files.exists(path)) {
            throw new FileNotFoundException("文件不存在: " + filePath);
        }

        File file = new File(filePath);
        return new FileInfo(
                file.getName(),
                filePath,
                file.length(),
                Files.getLastModifiedTime(path).toString()
        );
    }

    /**
     * 文件信息类
     */
    public static class FileInfo {
        private String fileName;
        private String filePath;
        private long fileSize;
        private String lastModified;

        public FileInfo(String fileName, String filePath, long fileSize, String lastModified) {
            this.fileName = fileName;
            this.filePath = filePath;
            this.fileSize = fileSize;
            this.lastModified = lastModified;
        }

        // Getters
        public String getFileName() { return fileName; }
        public String getFilePath() { return filePath; }
        public long getFileSize() { return fileSize; }
        public String getLastModified() { return lastModified; }

        @Override
        public String toString() {
            return String.format("文件: %s, 大小: %d bytes, 修改时间: %s",
                    fileName, fileSize, lastModified);
        }
    }
}