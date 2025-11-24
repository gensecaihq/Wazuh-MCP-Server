# Version Management Guide

## 🎯 **Safe, Focused Approach - No Breaking Changes**

This setup allows you to maintain independent versions for both transports:
- **Main branch**: STDIO transport (v2.1.0 → v2.x.x)  
- **MCP-Remote branch**: HTTP/SSE transport (v3.0.0 → v3.x.x)

## 🔧 **Quick Commands**

### **1. Check Current Status**
```bash
python3 tools/branch-sync.py status
```

### **2. Bump Version in Current Branch**
```bash
# In main branch (STDIO)
python3 tools/branch-sync.py bump 2.1.1

# In mcp-remote branch  
python3 tools/branch-sync.py bump 3.0.1
```

### **3. Coordinated Release (Both Branches)**
```bash
python3 tools/release-coordinator.py release 2.1.1 3.0.1
```

### **4. Check Both Branches Status**
```bash
python3 tools/release-coordinator.py status
```

## 📊 **Current Setup**

| Branch | Transport | Version | Use Case |
|--------|-----------|---------|----------|
| `main` | STDIO | v2.1.0 | Desktop/Claude integration |
| `mcp-remote` | HTTP/SSE | v3.0.0 | Enterprise/Remote deployment |

## 🚀 **Workflow Examples**

### **Release STDIO v2.1.1 (Bug Fix)**
```bash
git checkout main
python3 tools/branch-sync.py bump 2.1.1
git add .
git commit -m "Release v2.1.1: Bug fixes"
git push
```

### **Release Remote v3.1.0 (New Features)**  
```bash
git checkout mcp-remote
python3 tools/branch-sync.py bump 3.1.0
git add .
git commit -m "Release v3.1.0: New enterprise features"
git push
```

### **Coordinated Release (Both)**
```bash
python3 tools/release-coordinator.py release 2.2.0 3.1.0
# This automatically:
# - Updates both branches
# - Creates git tags
# - Commits changes
```

## ✅ **What This Doesn't Break**

- ✅ Existing code continues to work unchanged
- ✅ Current build/deployment processes remain intact  
- ✅ No import changes required
- ✅ No migration forced
- ✅ Both branches maintain full independence

## 📁 **Files Added** (Non-Breaking)

```
tools/
├── branch-sync.py           # Version management per branch
└── release-coordinator.py   # Cross-branch coordination

# Documentation
├── SAFE_MIGRATION_PLAN.md   # Future migration options
└── VERSION_MANAGEMENT.md    # This guide
```

## 🔄 **Daily Usage**

### **For STDIO Development (main branch)**
```bash
git checkout main
# Make changes
python3 tools/branch-sync.py bump 2.1.x
git commit -am "STDIO improvements v2.1.x"
```

### **For Remote Development (mcp-remote branch)**
```bash
git checkout mcp-remote  
# Make changes
python3 tools/branch-sync.py bump 3.0.x
git commit -am "Remote server improvements v3.0.x"
```

### **For Shared Feature (Apply to Both)**
```bash
# Apply change to main
git checkout main
# Make changes, test
python3 tools/branch-sync.py bump 2.1.x

# Apply same change to remote
git checkout mcp-remote
# Cherry-pick or manual apply
python3 tools/branch-sync.py bump 3.0.x
```

## 💡 **Tips**

1. **Always check status first**: `python3 tools/branch-sync.py status`
2. **Test before version bump**: Make sure everything works
3. **Use semantic versioning**: patch (x.x.1), minor (x.1.x), major (1.x.x)
4. **Coordinate shared changes**: Apply to both branches when needed
5. **Tag important releases**: Tags are created automatically

This approach keeps everything working while giving you the version control you need!