# Preset Definitions

프로그램 내부에서 다음과 같이 프리셋 값이 정의되어 있습니다.

```go
func applyPreset(cfg *Config) {
    var preset Config
    switch cfg.Preset {
    case "safe":
        preset.MaxDepth = 5
        preset.Scan = true
        preset.Workers = 2
        preset.ContentScan = false
    case "balanced":
        preset.MaxDepth = 12
        preset.Scan = true
        preset.Workers = 4
        preset.ContentScan = true
        preset.ContentMaxBytes = 65536
    case "deep":
        preset.MaxDepth = 0 // unlimited
        preset.Scan = true
        preset.Workers = 8
        preset.ContentScan = true
        preset.ContentMaxBytes = 131072
    case "handover":
        preset.MaxDepth = 8
        preset.Scan = true
        preset.Workers = 2
        preset.ContentScan = false
    case "offboarding":
        preset.MaxDepth = 20
        preset.Scan = true
        preset.Workers = 4
        preset.ContentScan = true
        preset.ContentMaxBytes = 65536
    default:
        return
    }
    // merge logic omitted
}
```

각 프리셋은 CLI/설정파일에서 직접 지정된 값이 있을 때만 덮어씌워집니다.