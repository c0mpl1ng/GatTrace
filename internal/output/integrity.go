package output

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"

	"GatTrace/internal/core"
)

// IntegrityManager 文件完整性管理器
type IntegrityManager struct {
	outputDir      string
	sessionManager *core.SessionManager
	fileHashes     map[string]string
}

// NewIntegrityManager 创建新的完整性管理器
func NewIntegrityManager(outputDir string, sessionManager *core.SessionManager) *IntegrityManager {
	return &IntegrityManager{
		outputDir:      outputDir,
		sessionManager: sessionManager,
		fileHashes:     make(map[string]string),
	}
}

// CalculateFileHash 计算单个文件的 SHA256 哈希
func (im *IntegrityManager) CalculateFileHash(filename string) (string, error) {
	filePath := filepath.Join(im.outputDir, filename)

	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file %s: %w", filename, err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", fmt.Errorf("failed to calculate hash for %s: %w", filename, err)
	}

	hash := fmt.Sprintf("%x", hasher.Sum(nil))
	im.fileHashes[filename] = hash

	return hash, nil
}

// CalculateAllHashes 计算输出目录中所有文件的哈希
func (im *IntegrityManager) CalculateAllHashes() error {
	// 清空现有哈希
	im.fileHashes = make(map[string]string)

	// 遍历输出目录
	err := filepath.Walk(im.outputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// 跳过目录和 manifest.json（稍后单独处理）
		if info.IsDir() || info.Name() == "manifest.json" {
			return nil
		}

		// 计算相对路径
		relPath, err := filepath.Rel(im.outputDir, path)
		if err != nil {
			return fmt.Errorf("failed to get relative path: %w", err)
		}

		// 计算哈希
		_, err = im.CalculateFileHash(relPath)
		if err != nil {
			return fmt.Errorf("failed to calculate hash for %s: %w", relPath, err)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to walk output directory: %w", err)
	}

	return nil
}

// CreateManifest 创建清单文件
func (im *IntegrityManager) CreateManifest() error {
	// 确保所有文件的哈希都已计算
	if err := im.CalculateAllHashes(); err != nil {
		return fmt.Errorf("failed to calculate hashes: %w", err)
	}

	// 创建清单条目
	var entries []core.ManifestEntry

	// 按文件名排序以确保一致性
	var filenames []string
	for filename := range im.fileHashes {
		filenames = append(filenames, filename)
	}
	sort.Strings(filenames)

	for _, filename := range filenames {
		hash := im.fileHashes[filename]

		// 获取文件大小
		filePath := filepath.Join(im.outputDir, filename)
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			return fmt.Errorf("failed to get file info for %s: %w", filename, err)
		}

		entries = append(entries, core.ManifestEntry{
			Filename: filename,
			Hash:     hash,
			Size:     fileInfo.Size(),
		})
	}

	// 创建清单对象
	var manifest core.Manifest
	if im.sessionManager != nil {
		manifest = core.Manifest{
			Metadata: im.sessionManager.GetMetadata(),
			Files:    entries,
		}
	} else {
		// 如果没有会话管理器，创建一个基本的清单
		manifest = core.Manifest{
			Metadata: core.Metadata{
				SessionID:        "unknown",
				Hostname:         "unknown",
				Platform:         "unknown",
				CollectedAt:      core.NormalizeTimestamp(time.Now()),
				CollectorVersion: "unknown",
			},
			Files: entries,
		}
	}

	// 写入清单文件
	jsonSerializer := NewJSONSerializer(im.outputDir, true)

	// 临时写入清单文件以计算其哈希
	if err := jsonSerializer.WriteJSON("manifest.json", manifest); err != nil {
		return fmt.Errorf("failed to write manifest file: %w", err)
	}

	// 计算清单文件本身的哈希
	manifestHash, err := im.calculateManifestHash()
	if err != nil {
		return fmt.Errorf("failed to calculate manifest hash: %w", err)
	}

	// 更新清单对象包含自身哈希
	manifest.ManifestHash = manifestHash

	// 重新写入包含哈希的清单文件
	if err := jsonSerializer.WriteJSON("manifest.json", manifest); err != nil {
		return fmt.Errorf("failed to write final manifest file: %w", err)
	}

	return nil
}

// calculateManifestHash 计算清单文件的哈希
func (im *IntegrityManager) calculateManifestHash() (string, error) {
	manifestPath := filepath.Join(im.outputDir, "manifest.json")

	file, err := os.Open(manifestPath)
	if err != nil {
		return "", fmt.Errorf("failed to open manifest file: %w", err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", fmt.Errorf("failed to calculate manifest hash: %w", err)
	}

	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}

// GetFileHash 获取指定文件的哈希
func (im *IntegrityManager) GetFileHash(filename string) (string, bool) {
	hash, exists := im.fileHashes[filename]
	return hash, exists
}

// GetAllHashes 获取所有文件的哈希
func (im *IntegrityManager) GetAllHashes() map[string]string {
	// 返回副本以防止外部修改
	result := make(map[string]string)
	for k, v := range im.fileHashes {
		result[k] = v
	}
	return result
}

// VerifyIntegrity 验证文件完整性
func (im *IntegrityManager) VerifyIntegrity() error {
	for filename, expectedHash := range im.fileHashes {
		currentHash, err := im.CalculateFileHash(filename)
		if err != nil {
			return fmt.Errorf("failed to calculate current hash for %s: %w", filename, err)
		}

		if currentHash != expectedHash {
			return fmt.Errorf("integrity check failed for %s: expected %s, got %s",
				filename, expectedHash, currentHash)
		}
	}

	return nil
}
